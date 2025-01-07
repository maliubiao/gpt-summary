Response:
Let's break down the thought process for analyzing this `module.cc` file.

1. **Understand the Context:** The file path `v8/src/objects/module.cc` immediately tells us this is part of V8's object system, specifically dealing with modules. The `.cc` extension indicates C++ source code. Keywords like "Copyright," "BSD-style license," and `#include` further confirm this.

2. **Initial Scan for Key Structures:** Look for the main class or struct being defined. Here, it's the `Module` class. This is the central concept.

3. **Identify Key Data Members (Implicit):** Even without seeing the `.h` file, the code hints at data members. The `status()` method and `set_status()` suggest a state variable. `exception()` and `set_exception()` point to error handling. `module_namespace()` and `set_module_namespace()` indicate a relationship with namespace objects. The presence of `SourceTextModule` and `SyntheticModule` casts suggests `Module` is likely an abstract base or has subclasses.

4. **Analyze Key Methods:**  Go through the methods and understand their purpose. Pay attention to:
    * **Status Management:** `SetStatus`, `RecordError`, `StatusString`. These are crucial for understanding the module lifecycle.
    * **Instantiation:** `Instantiate`, `PrepareInstantiate`, `FinishInstantiate`. This is a core part of the module loading process.
    * **Evaluation:** `Evaluate`. This is how module code is executed.
    * **Resolution:** `ResolveExport`. This is about finding exported values.
    * **Namespace Management:** `GetModuleNamespace`, `HasExport`, `GetExport`, `DefineOwnProperty`. These methods handle how module exports are accessed.
    * **Resetting:** `Reset`, `ResetGraph`. Important for error recovery and potentially reloading.
    * **Asynchronous Behavior:** `IsGraphAsync`. Hints at handling `async`/`await` in modules.

5. **Look for Helper Functions and Data Structures:** Note the anonymous namespace with `PrintModuleName`, `PrintStatusTransition`, and `PrintStatusMessage`. These are debugging aids. The use of `unordered_map`, `unordered_set`, `Zone`, and `ZoneVector` indicates memory management strategies and data organization.

6. **Connect to JavaScript Concepts:** Think about how these C++ methods relate to JavaScript module features:
    * `import`/`export` statements map to the `ResolveExport` logic and namespace creation.
    * The module lifecycle (unlinked, linking, evaluated, etc.) reflects the stages of module loading in JavaScript.
    * Errors during module loading are handled by `RecordError`.
    * `async`/`await` in modules are related to the `IsGraphAsync` function.

7. **Consider Edge Cases and Error Handling:** The `RecordError` method explicitly handles errors. The checks in `Evaluate` for `kErrored` status are important. The `DCHECK` macros throughout the code highlight internal consistency checks.

8. **Infer Relationships Between Classes:** The frequent casting between `Module`, `SourceTextModule`, and `SyntheticModule` suggests an inheritance or composition relationship. The interaction with `JSModuleNamespace`, `Cell`, and `ObjectHashTable` reveals the underlying data structures used to represent modules.

9. **Think About Potential User Errors:** Consider common mistakes developers make when working with JavaScript modules, such as:
    * Circular dependencies (which the V8 code needs to handle).
    * Referencing uninitialized exports.
    * Trying to redefine exports.
    * Errors in the module code itself.

10. **Address Specific Questions in the Prompt:**  Go back to the prompt and answer each part systematically:
    * **Functionality Summary:**  Combine the insights from the previous steps to write a concise summary.
    * **Torque:**  Check the file extension; `.cc` means it's C++, not Torque.
    * **JavaScript Relationship:** Provide concrete JavaScript examples that illustrate the C++ code's purpose.
    * **Code Logic Reasoning:** Choose a method with clear input and output (e.g., `SetStatus`) and demonstrate the logic.
    * **Common Programming Errors:** Give relevant JavaScript examples of errors that the V8 code is designed to handle.

11. **Review and Refine:**  Read through the analysis to ensure clarity, accuracy, and completeness. Check for any inconsistencies or missing information. For example, ensure the JavaScript examples accurately reflect the underlying C++ logic being described.

By following these steps, we can systematically analyze a complex C++ source file like `module.cc` and understand its role within the larger V8 engine and its connection to JavaScript.
This C++ source file, `v8/src/objects/module.cc`, is a core component of the V8 JavaScript engine responsible for **representing and managing JavaScript modules**. It defines the `Module` class and related functionalities, which are crucial for implementing the ECMAScript module system in V8.

Here's a breakdown of its key functionalities:

**1. Module Representation:**

*   **Defines the `Module` class:** This class serves as the base for different types of modules, like `SourceTextModule` (for regular JavaScript files) and `SyntheticModule` (for programmatically created modules).
*   **Manages Module Status:** The `Module` class tracks the lifecycle of a module using an enumeration (`Status`). The statuses include:
    *   `kUnlinked`: The module has been parsed but not yet linked.
    *   `kPreLinking`: The linking process has started.
    *   `kLinking`: The module is currently being linked.
    *   `kLinked`: The module has been successfully linked.
    *   `kEvaluating`: The module's code is currently being evaluated.
    *   `kEvaluatingAsync`: The module's top-level await is being evaluated.
    *   `kEvaluated`: The module's code has been successfully evaluated.
    *   `kErrored`: An error occurred during linking or evaluation.
*   **Stores Module Metadata:**  The `Module` class holds information about the module, such as its exports, exception (if an error occurred), and the associated namespace object.

**2. Module Linking:**

*   **`Instantiate()`:** This is the main entry point for initiating the module instantiation process. It orchestrates the steps needed to prepare a module for evaluation, including resolving dependencies.
*   **`PrepareInstantiate()` and `FinishInstantiate()`:** These methods break down the instantiation process into smaller steps. `PrepareInstantiate` handles initial setup, while `FinishInstantiate` recursively processes the module's dependencies.
*   **`ResolveExport()`:** This method is responsible for resolving an export name within a module, potentially traversing through imported modules.

**3. Module Evaluation:**

*   **`Evaluate()`:** This method triggers the execution of the module's code. It handles different module statuses and ensures that evaluation happens at the appropriate time.
*   **Manages Top-Level Await:** The code includes logic to handle modules with top-level `await`, managing the `kEvaluatingAsync` status.

**4. Module Namespace:**

*   **`GetModuleNamespace()`:** This crucial method creates and returns the namespace object for a module. The namespace object provides access to the module's exported values.
*   **`JSModuleNamespace::HasExport()` and `JSModuleNamespace::GetExport()`:** These methods on the `JSModuleNamespace` class allow checking if an export exists and retrieving its value, respectively.

**5. Error Handling:**

*   **`RecordError()`:**  This method is called when an error occurs during linking or evaluation. It sets the module's status to `kErrored` and stores the error object.
*   **`GetException()`:**  Retrieves the error object associated with a module that has encountered an error.
*   **`ResetGraph()` and `Reset()`:** These methods are used to reset the state of a module graph, often in response to errors during instantiation.

**6. Debugging and Tracing:**

*   The code includes debugging utilities (within `#ifdef DEBUG`) to print module status transitions and instantiation messages, which are helpful for understanding the module loading process.

**Is `v8/src/objects/module.cc` a Torque Source File?**

No, the file extension `.cc` indicates that `v8/src/objects/module.cc` is a **C++ source file**, not a Torque source file. Torque files typically have the extension `.tq`.

**Relationship with JavaScript and Examples:**

The functionalities in `module.cc` directly support the JavaScript module system. Here are some examples:

```javascript
// moduleA.js
export const message = "Hello from module A";
export function greet(name) {
  return `Hello, ${name}!`;
}

// moduleB.js
import { message, greet } from './moduleA.js';

console.log(message); // Accessing an exported constant
console.log(greet("World")); // Accessing an exported function
```

**How `module.cc` works behind the scenes for the above example:**

1. **Parsing:** When the JavaScript engine encounters `import` and `export` statements, the parser creates internal representations of these modules. This involves creating `SourceTextModule` objects (handled by classes related to `Module`).
2. **Instantiation (Linking):**
    *   The engine uses `Module::Instantiate` (or its related methods) to resolve the dependency on `./moduleA.js` from `moduleB.js`. This involves finding and loading the `moduleA.js` file.
    *   `SourceTextModule::ResolveExport` would be used to verify that `moduleA.js` actually exports `message` and `greet`.
    *   The statuses of both modules would transition from `kUnlinked` to `kLinking` and eventually to `kLinked` if successful.
3. **Namespace Creation:** `Module::GetModuleNamespace` would be called for `moduleA.js` to create a namespace object. This object internally stores references to the exported `message` and `greet`.
4. **Evaluation:**
    *   `Module::Evaluate` would be called for both modules.
    *   When `console.log(message)` is executed in `moduleB.js`, the engine uses the namespace object of `moduleA.js` to retrieve the value of `message`. `JSModuleNamespace::GetExport` would be the method handling this lookup.

**Code Logic Reasoning with Assumptions:**

Let's consider the `SetStatus` method:

```c++
void Module::SetStatus(Status new_status) {
  DisallowGarbageCollection no_gc;
  DCHECK_LE(status(), new_status);
  DCHECK_NE(new_status, Module::kErrored);
  SetStatusInternal(*this, new_status);
}
```

**Assumptions:**

*   **Input:** A `Module` object (represented by `*this`) and a new `Module::Status` (`new_status`).
*   **Current Status:** Let's assume the module's current `status()` is `kUnlinked`.
*   **New Status:** Let's assume `new_status` is `kLinking`.

**Logic:**

1. `DisallowGarbageCollection no_gc;`: This prevents garbage collection from happening during this operation, ensuring the module object remains valid.
2. `DCHECK_LE(status(), new_status);`: This assertion checks if the current status is less than or equal to the new status. In our case, `kUnlinked` (0) is less than `kLinking` (2), so the assertion passes. This enforces the logical progression of module states.
3. `DCHECK_NE(new_status, Module::kErrored);`: This assertion ensures we are not directly setting the status to `kErrored` using this method. Errors are typically recorded via `RecordError`.
4. `SetStatusInternal(*this, new_status);`: This calls an internal helper function to actually update the module's status to `kLinking`. The internal function might include additional debugging output (as seen in the code).

**Output:**

*   The module's internal `status` will be updated to `kLinking`.
*   If debugging is enabled, a trace message might be printed indicating the status transition.

**Common Programming Errors (JavaScript) related to `module.cc` functionality:**

1. **Circular Dependencies:**

    ```javascript
    // a.js
    import { b } from './b.js';
    export const a = 1;
    console.log(b);

    // b.js
    import { a } from './a.js';
    export const b = 2;
    console.log(a);
    ```

    This can lead to errors during the linking phase, potentially resulting in a module getting stuck in a linking state or throwing a runtime error if the dependencies are not properly resolved before access. `module.cc`'s linking logic needs to handle these cycles gracefully (or detect and report them).

2. **Accessing Uninitialized Exports (Temporal Dead Zone):**

    ```javascript
    // moduleA.js
    export let counter = 0;
    counter++;

    // moduleB.js
    import { counter } from './moduleA.js';
    console.log(counter); // May result in an error if accessed too early
    ```

    JavaScript has a temporal dead zone for variables declared with `let` and `const`. If you try to access an imported binding before its module has finished evaluating, you'll get a `ReferenceError`. The logic in `JSModuleNamespace::GetExport` needs to handle this, often by checking if the underlying `Cell` (which holds the variable's value) has been initialized.

3. **Trying to Re-export or Modify Immutable Exports:**

    ```javascript
    // moduleA.js
    export const MESSAGE = "Hello";

    // moduleB.js
    import { MESSAGE } from './moduleA.js';
    // MESSAGE = "Goodbye"; // This will cause an error
    ```

    Exports declared with `const` are immutable. Trying to reassign them in the importing module will lead to a `TypeError`. While `module.cc` doesn't directly enforce this at the JavaScript level, the underlying representation and the way namespaces are created ensure that these bindings are read-only from the perspective of the importing module.

In summary, `v8/src/objects/module.cc` is a fundamental piece of V8's module implementation, handling the core aspects of module representation, linking, evaluation, and namespace management. It directly supports the features and semantics of JavaScript modules as defined by the ECMAScript standard.

Prompt: 
```
这是目录为v8/src/objects/module.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/module.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/objects/module.h"

#include <unordered_map>
#include <unordered_set>

#include "src/api/api-inl.h"
#include "src/ast/modules.h"
#include "src/builtins/accessors.h"
#include "src/common/assert-scope.h"
#include "src/heap/heap-inl.h"
#include "src/objects/cell-inl.h"
#include "src/objects/hash-table-inl.h"
#include "src/objects/js-generator-inl.h"
#include "src/objects/module-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/property-descriptor.h"
#include "src/objects/source-text-module.h"
#include "src/objects/synthetic-module-inl.h"
#include "src/utils/ostreams.h"

namespace v8 {
namespace internal {

namespace {
#ifdef DEBUG
void PrintModuleName(Tagged<Module> module, std::ostream& os) {
  if (IsSourceTextModule(module)) {
    Print(Cast<SourceTextModule>(module)->GetScript()->GetNameOrSourceURL(),
          os);
  } else {
    Print(Cast<SyntheticModule>(module)->name(), os);
  }
#ifndef OBJECT_PRINT
  os << "\n";
#endif  // OBJECT_PRINT
}

void PrintStatusTransition(Tagged<Module> module, Module::Status old_status) {
  if (!v8_flags.trace_module_status) return;
  StdoutStream os;
  os << "Changing module status from " << Module::StatusString(old_status)
     << " to "
     << Module::StatusString(static_cast<Module::Status>(module->status()))
     << " for ";
  PrintModuleName(module, os);
}

void PrintStatusMessage(Tagged<Module> module, const char* message) {
  if (!v8_flags.trace_module_status) return;
  StdoutStream os;
  os << "Instantiating module ";
  PrintModuleName(module, os);
}
#endif  // DEBUG

void SetStatusInternal(Tagged<Module> module, Module::Status new_status) {
  DisallowGarbageCollection no_gc;
#ifdef DEBUG
  Module::Status old_status = static_cast<Module::Status>(module->status());
  module->set_status(new_status);
  PrintStatusTransition(module, old_status);
#else
  module->set_status(new_status);
#endif  // DEBUG
}

}  // end namespace

#ifdef DEBUG
// static
const char* Module::StatusString(Module::Status status) {
  switch (status) {
    case Module::kUnlinked:
      return "Unlinked";
    case Module::kPreLinking:
      return "PreLinking";
    case Module::kLinking:
      return "Linking";
    case Module::kLinked:
      return "Linked";
    case Module::kEvaluating:
      return "Evaluating";
    case Module::kEvaluatingAsync:
      return "EvaluatingAsync";
    case Module::kEvaluated:
      return "Evaluated";
    case Module::kErrored:
      return "Errored";
  }
}
#endif  // DEBUG

void Module::SetStatus(Status new_status) {
  DisallowGarbageCollection no_gc;
  DCHECK_LE(status(), new_status);
  DCHECK_NE(new_status, Module::kErrored);
  SetStatusInternal(*this, new_status);
}

void Module::RecordError(Isolate* isolate, Tagged<Object> error) {
  DisallowGarbageCollection no_gc;
  // Allow overriding exceptions with termination exceptions.
  DCHECK_IMPLIES(isolate->is_catchable_by_javascript(error),
                 IsTheHole(exception(), isolate));
  DCHECK(!IsTheHole(error, isolate));
  if (IsSourceTextModule(*this)) {
    // Revert to minmal SFI in case we have already been instantiating or
    // evaluating.
    auto self = Cast<SourceTextModule>(*this);
    self->set_code(self->GetSharedFunctionInfo());
  }
  SetStatusInternal(*this, Module::kErrored);
  if (isolate->is_catchable_by_javascript(error)) {
    set_exception(error);
  } else {
    // v8::TryCatch uses `null` for termination exceptions.
    set_exception(ReadOnlyRoots(isolate).null_value());
  }
}

void Module::ResetGraph(Isolate* isolate, Handle<Module> module) {
  DCHECK_NE(module->status(), kEvaluating);
  if (module->status() != kPreLinking && module->status() != kLinking) {
    return;
  }

  DirectHandle<FixedArray> requested_modules =
      IsSourceTextModule(*module)
          ? Handle<FixedArray>(
                Cast<SourceTextModule>(*module)->requested_modules(), isolate)
          : Handle<FixedArray>();
  Reset(isolate, module);

  if (!IsSourceTextModule(*module)) {
    DCHECK(IsSyntheticModule(*module));
    return;
  }
  for (int i = 0; i < requested_modules->length(); ++i) {
    Handle<Object> descendant(requested_modules->get(i), isolate);
    if (IsModule(*descendant)) {
      ResetGraph(isolate, Cast<Module>(descendant));
    } else {
      // The requested module is either an undefined or a WasmModule object.
#if V8_ENABLE_WEBASSEMBLY
      DCHECK(IsUndefined(*descendant, isolate) ||
             IsWasmModuleObject(*descendant));
#else
      DCHECK(IsUndefined(*descendant, isolate));
#endif
    }
  }
}

void Module::Reset(Isolate* isolate, Handle<Module> module) {
  DCHECK(module->status() == kPreLinking || module->status() == kLinking);
  DCHECK(IsTheHole(module->exception(), isolate));
  // The namespace object cannot exist, because it would have been created
  // by RunInitializationCode, which is called only after this module's SCC
  // succeeds instantiation.
  DCHECK(!IsJSModuleNamespace(module->module_namespace()));
  const int export_count =
      IsSourceTextModule(*module)
          ? Cast<SourceTextModule>(*module)->regular_exports()->length()
          : Cast<SyntheticModule>(*module)->export_names()->length();
  DirectHandle<ObjectHashTable> exports =
      ObjectHashTable::New(isolate, export_count);

  if (IsSourceTextModule(*module)) {
    SourceTextModule::Reset(isolate, Cast<SourceTextModule>(module));
  }

  module->set_exports(*exports);
  SetStatusInternal(*module, kUnlinked);
}

Tagged<Object> Module::GetException() {
  DisallowGarbageCollection no_gc;
  DCHECK_EQ(status(), Module::kErrored);
  DCHECK(!IsTheHole(exception()));
  return exception();
}

MaybeHandle<Cell> Module::ResolveExport(Isolate* isolate, Handle<Module> module,
                                        Handle<String> module_specifier,
                                        Handle<String> export_name,
                                        MessageLocation loc, bool must_resolve,
                                        Module::ResolveSet* resolve_set) {
  DCHECK_GE(module->status(), kPreLinking);
  DCHECK_NE(module->status(), kEvaluating);

  if (IsSourceTextModule(*module)) {
    return SourceTextModule::ResolveExport(
        isolate, Cast<SourceTextModule>(module), module_specifier, export_name,
        loc, must_resolve, resolve_set);
  } else {
    return SyntheticModule::ResolveExport(
        isolate, Cast<SyntheticModule>(module), module_specifier, export_name,
        loc, must_resolve);
  }
}

bool Module::Instantiate(Isolate* isolate, Handle<Module> module,
                         v8::Local<v8::Context> context,
                         v8::Module::ResolveModuleCallback module_callback,
                         v8::Module::ResolveSourceCallback source_callback) {
#ifdef DEBUG
  PrintStatusMessage(*module, "Instantiating module ");
#endif  // DEBUG

  if (!PrepareInstantiate(isolate, module, context, module_callback,
                          source_callback)) {
    ResetGraph(isolate, module);
    DCHECK_EQ(module->status(), kUnlinked);
    return false;
  }
  Zone zone(isolate->allocator(), ZONE_NAME);
  ZoneForwardList<Handle<SourceTextModule>> stack(&zone);
  unsigned dfs_index = 0;
  if (!FinishInstantiate(isolate, module, &stack, &dfs_index, &zone)) {
    ResetGraph(isolate, module);
    DCHECK_EQ(module->status(), kUnlinked);
    return false;
  }
  DCHECK(module->status() == kLinked || module->status() == kEvaluated ||
         module->status() == kEvaluatingAsync || module->status() == kErrored);
  DCHECK(stack.empty());
  return true;
}

bool Module::PrepareInstantiate(
    Isolate* isolate, Handle<Module> module, v8::Local<v8::Context> context,
    v8::Module::ResolveModuleCallback module_callback,
    v8::Module::ResolveSourceCallback source_callback) {
  DCHECK_NE(module->status(), kEvaluating);
  DCHECK_NE(module->status(), kLinking);
  if (module->status() >= kPreLinking) return true;
  module->SetStatus(kPreLinking);
  STACK_CHECK(isolate, false);

  if (IsSourceTextModule(*module)) {
    return SourceTextModule::PrepareInstantiate(
        isolate, Cast<SourceTextModule>(module), context, module_callback,
        source_callback);
  } else {
    return SyntheticModule::PrepareInstantiate(
        isolate, Cast<SyntheticModule>(module), context);
  }
}

bool Module::FinishInstantiate(Isolate* isolate, Handle<Module> module,
                               ZoneForwardList<Handle<SourceTextModule>>* stack,
                               unsigned* dfs_index, Zone* zone) {
  DCHECK_NE(module->status(), kEvaluating);
  if (module->status() >= kLinking) return true;
  DCHECK_EQ(module->status(), kPreLinking);
  STACK_CHECK(isolate, false);

  if (IsSourceTextModule(*module)) {
    return SourceTextModule::FinishInstantiate(
        isolate, Cast<SourceTextModule>(module), stack, dfs_index, zone);
  } else {
    return SyntheticModule::FinishInstantiate(isolate,
                                              Cast<SyntheticModule>(module));
  }
}

MaybeHandle<Object> Module::Evaluate(Isolate* isolate, Handle<Module> module) {
#ifdef DEBUG
  PrintStatusMessage(*module, "Evaluating module ");
#endif  // DEBUG
  int module_status = module->status();

  // In the event of errored evaluation, return a rejected promise.
  if (module_status == kErrored) {
    // If we have a top level capability we assume it has already been
    // rejected, and return it here. Otherwise create a new promise and
    // reject it with the module's exception.
    if (IsJSPromise(module->top_level_capability())) {
      Handle<JSPromise> top_level_capability(
          Cast<JSPromise>(module->top_level_capability()), isolate);
      DCHECK(top_level_capability->status() == Promise::kRejected &&
             top_level_capability->result() == module->exception());
      return top_level_capability;
    }
    Handle<JSPromise> capability = isolate->factory()->NewJSPromise();
    JSPromise::Reject(capability, handle(module->exception(), isolate));
    return capability;
  }

  // Start of Evaluate () Concrete Method
  // 2. Assert: module.[[Status]] is one of LINKED, EVALUATING-ASYNC, or
  //    EVALUATED.
  CHECK(module_status == kLinked || module_status == kEvaluatingAsync ||
        module_status == kEvaluated);

  // 3. If module.[[Status]] is either EVALUATING-ASYNC or EVALUATED, set module
  //    to module.[[CycleRoot]].
  // A Synthetic Module has no children so it is its own cycle root.
  if (module_status >= kEvaluatingAsync && IsSourceTextModule(*module)) {
    module = Cast<SourceTextModule>(module)->GetCycleRoot(isolate);
  }

  // 4. If module.[[TopLevelCapability]] is not EMPTY, then
  //    a. Return module.[[TopLevelCapability]].[[Promise]].
  if (IsJSPromise(module->top_level_capability())) {
    return handle(Cast<JSPromise>(module->top_level_capability()), isolate);
  }
  DCHECK(IsUndefined(module->top_level_capability()));

  if (IsSourceTextModule(*module)) {
    return SourceTextModule::Evaluate(isolate, Cast<SourceTextModule>(module));
  } else {
    return SyntheticModule::Evaluate(isolate, Cast<SyntheticModule>(module));
  }
}

Handle<JSModuleNamespace> Module::GetModuleNamespace(Isolate* isolate,
                                                     Handle<Module> module) {
  Handle<HeapObject> object(module->module_namespace(), isolate);
  ReadOnlyRoots roots(isolate);
  if (!IsUndefined(*object, roots)) {
    // Namespace object already exists.
    return Cast<JSModuleNamespace>(object);
  }

  // Collect the export names.
  Zone zone(isolate->allocator(), ZONE_NAME);
  UnorderedModuleSet visited(&zone);

  if (IsSourceTextModule(*module)) {
    SourceTextModule::FetchStarExports(isolate, Cast<SourceTextModule>(module),
                                       &zone, &visited);
  }

  DirectHandle<ObjectHashTable> exports(module->exports(), isolate);
  ZoneVector<IndirectHandle<String>> names(&zone);
  names.reserve(exports->NumberOfElements());
  for (InternalIndex i : exports->IterateEntries()) {
    Tagged<Object> key;
    if (!exports->ToKey(roots, i, &key)) continue;
    names.push_back(handle(Cast<String>(key), isolate));
  }
  DCHECK_EQ(static_cast<int>(names.size()), exports->NumberOfElements());

  // Sort them alphabetically.
  std::sort(names.begin(), names.end(),
            [&isolate](IndirectHandle<String> a, IndirectHandle<String> b) {
              return String::Compare(isolate, a, b) ==
                     ComparisonResult::kLessThan;
            });

  // Create the namespace object (initially empty).
  Handle<JSModuleNamespace> ns = isolate->factory()->NewJSModuleNamespace();
  ns->set_module(*module);
  module->set_module_namespace(*ns);

  // Create the properties in the namespace object. Transition the object
  // to dictionary mode so that property addition is faster.
  PropertyAttributes attr = DONT_DELETE;
  JSObject::NormalizeProperties(isolate, ns, CLEAR_INOBJECT_PROPERTIES,
                                static_cast<int>(names.size()),
                                "JSModuleNamespace");
  JSObject::NormalizeElements(ns);
  for (const auto& name : names) {
    uint32_t index = 0;
    if (name->AsArrayIndex(&index)) {
      JSObject::SetNormalizedElement(
          ns, index, Accessors::MakeModuleNamespaceEntryInfo(isolate, name),
          PropertyDetails(PropertyKind::kAccessor, attr,
                          PropertyCellType::kMutable));
    } else {
      JSObject::SetNormalizedProperty(
          ns, name, Accessors::MakeModuleNamespaceEntryInfo(isolate, name),
          PropertyDetails(PropertyKind::kAccessor, attr,
                          PropertyCellType::kMutable));
    }
  }
  JSObject::PreventExtensions(isolate, ns, kThrowOnError).ToChecked();

  // Optimize the namespace object as a prototype, for two reasons:
  // - The object's map is guaranteed not to be shared. ICs rely on this.
  // - We can store a pointer from the map back to the namespace object.
  //   Turbofan can use this for inlining the access.
  JSObject::OptimizeAsPrototype(ns);

  DirectHandle<PrototypeInfo> proto_info =
      Map::GetOrCreatePrototypeInfo(ns, isolate);
  proto_info->set_module_namespace(*ns);
  return ns;
}

bool JSModuleNamespace::HasExport(Isolate* isolate, Handle<String> name) {
  DirectHandle<Object> object(module()->exports()->Lookup(name), isolate);
  return !IsTheHole(*object, isolate);
}

MaybeHandle<Object> JSModuleNamespace::GetExport(Isolate* isolate,
                                                 Handle<String> name) {
  DirectHandle<Object> object(module()->exports()->Lookup(name), isolate);
  if (IsTheHole(*object, isolate)) {
    return isolate->factory()->undefined_value();
  }

  Handle<Object> value(Cast<Cell>(*object)->value(), isolate);
  if (IsTheHole(*value, isolate)) {
    // According to https://tc39.es/ecma262/#sec-InnerModuleLinking
    // step 10 and
    // https://tc39.es/ecma262/#sec-source-text-module-record-initialize-environment
    // step 8-25, variables must be declared in Link. And according to
    // https://tc39.es/ecma262/#sec-module-namespace-exotic-objects-get-p-receiver,
    // here accessing uninitialized variable error should be throwed.
    THROW_NEW_ERROR(isolate,
                    NewReferenceError(
                        MessageTemplate::kAccessedUninitializedVariable, name));
  }

  return value;
}

Maybe<PropertyAttributes> JSModuleNamespace::GetPropertyAttributes(
    LookupIterator* it) {
  DirectHandle<JSModuleNamespace> object = it->GetHolder<JSModuleNamespace>();
  Handle<String> name = Cast<String>(it->GetName());
  DCHECK_EQ(it->state(), LookupIterator::ACCESSOR);

  Isolate* isolate = it->isolate();

  DirectHandle<Object> lookup(object->module()->exports()->Lookup(name),
                              isolate);
  if (IsTheHole(*lookup, isolate)) return Just(ABSENT);

  DirectHandle<Object> value(Cast<Cell>(lookup)->value(), isolate);
  if (IsTheHole(*value, isolate)) {
    isolate->Throw(*isolate->factory()->NewReferenceError(
        MessageTemplate::kNotDefined, name));
    return Nothing<PropertyAttributes>();
  }

  return Just(it->property_attributes());
}

// ES
// https://tc39.es/ecma262/#sec-module-namespace-exotic-objects-defineownproperty-p-desc
// static
Maybe<bool> JSModuleNamespace::DefineOwnProperty(
    Isolate* isolate, Handle<JSModuleNamespace> object, Handle<Object> key,
    PropertyDescriptor* desc, Maybe<ShouldThrow> should_throw) {
  // 1. If Type(P) is Symbol, return OrdinaryDefineOwnProperty(O, P, Desc).
  if (IsSymbol(*key)) {
    return OrdinaryDefineOwnProperty(isolate, object, key, desc, should_throw);
  }

  // 2. Let current be ? O.[[GetOwnProperty]](P).
  PropertyKey lookup_key(isolate, key);
  LookupIterator it(isolate, object, lookup_key, LookupIterator::OWN);
  PropertyDescriptor current;
  Maybe<bool> has_own = GetOwnPropertyDescriptor(&it, &current);
  MAYBE_RETURN(has_own, Nothing<bool>());

  // 3. If current is undefined, return false.
  // 4. If Desc.[[Configurable]] is present and has value true, return false.
  // 5. If Desc.[[Enumerable]] is present and has value false, return false.
  // 6. If ! IsAccessorDescriptor(Desc) is true, return false.
  // 7. If Desc.[[Writable]] is present and has value false, return false.
  // 8. If Desc.[[Value]] is present, return
  //    SameValue(Desc.[[Value]], current.[[Value]]).
  if (!has_own.FromJust() ||
      (desc->has_configurable() && desc->configurable()) ||
      (desc->has_enumerable() && !desc->enumerable()) ||
      PropertyDescriptor::IsAccessorDescriptor(desc) ||
      (desc->has_writable() && !desc->writable()) ||
      (desc->has_value() &&
       !Object::SameValue(*desc->value(), *current.value()))) {
    RETURN_FAILURE(isolate, GetShouldThrow(isolate, should_throw),
                   NewTypeError(MessageTemplate::kRedefineDisallowed, key));
  }

  return Just(true);
}

bool Module::IsGraphAsync(Isolate* isolate) const {
  DisallowGarbageCollection no_gc;

  // Only SourceTextModules may be async.
  if (!IsSourceTextModule(*this)) return false;
  Tagged<SourceTextModule> root = Cast<SourceTextModule>(*this);

  Zone zone(isolate->allocator(), ZONE_NAME);
  const size_t bucket_count = 2;
  ZoneUnorderedSet<Tagged<Module>, Module::Hash> visited(&zone, bucket_count);
  ZoneVector<Tagged<SourceTextModule>> worklist(&zone);
  visited.insert(root);
  worklist.push_back(root);

  do {
    Tagged<SourceTextModule> current = worklist.back();
    worklist.pop_back();
    DCHECK_GE(current->status(), kLinked);

    if (current->has_toplevel_await()) return true;
    Tagged<FixedArray> requested_modules = current->requested_modules();
    for (int i = 0, length = requested_modules->length(); i < length; ++i) {
      Tagged<Module> descendant = Cast<Module>(requested_modules->get(i));
      if (IsSourceTextModule(descendant)) {
        const bool cycle = !visited.insert(descendant).second;
        if (!cycle) worklist.push_back(Cast<SourceTextModule>(descendant));
      }
    }
  } while (!worklist.empty());

  return false;
}

}  // namespace internal
}  // namespace v8

"""

```