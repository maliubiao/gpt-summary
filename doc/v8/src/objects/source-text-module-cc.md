Response:
Let's break down the thought process for analyzing the `source-text-module.cc` file.

**1. Initial Understanding and Context:**

* **File Path:**  The path `v8/src/objects/source-text-module.cc` immediately tells us this is part of the V8 JavaScript engine, specifically within the `objects` directory. This suggests it's dealing with the runtime representation of source text modules.
* **File Extension:** `.cc` indicates C++ source code. The prompt explicitly mentions checking for `.tq` (Torque), which is not the case here.
* **Copyright Notice:**  Confirms it's a V8 project file.

**2. High-Level Purpose (Deduction from Includes and Namespaces):**

* **Includes:** Look at the `#include` directives. These are crucial for understanding dependencies and what functionalities are being used:
    * `"src/objects/source-text-module.h"`:  The corresponding header file, likely containing the declaration of the `SourceTextModule` class and related structures.
    * `"src/api/api-inl.h"`:  Interaction with V8's public API.
    * `"src/ast/modules.h"`:  Abstract Syntax Tree (AST) related to modules, indicating parsing and representation of module structure.
    * `"src/builtins/accessors.h"`:  Mechanisms for accessing object properties, suggesting module exports/imports.
    * `"src/common/assert-scope.h"`:  Assertions for debugging and correctness checking.
    * `"src/objects/js-generator-inl.h"`:  Dealing with JavaScript generators, which are relevant for module execution.
    * `"src/objects/module-inl.h"`:  Base class or related functionality for modules.
    * `"src/objects/objects-inl.h"`:  Core V8 object representations.
    * `"src/objects/shared-function-info.h"`:  Information about functions, crucial for module initialization.
    * `"src/utils/ostreams.h"`:  Output streams, likely used for debugging or tracing.
* **Namespace:** `namespace v8 { namespace internal { ... } }` confirms this is internal V8 implementation.

* **Initial Hypothesis:**  This file likely defines the runtime behavior and data structures for handling ECMAScript modules that are loaded from source text (as opposed to other module types like WASM modules). It probably deals with:
    * Parsing and representing module structure (imports, exports).
    * Linking modules together.
    * Executing module code.
    * Managing the module namespace.

**3. Examining Key Structures and Functions:**

* **Helper Structs/Classes:**
    * `StringHandleHash`, `StringHandleEqual`:  Custom hash and equality functions for `Handle<String>`, suggesting the use of hash tables for storing string-based data (like export/import names).
    * `UnorderedStringSet`, `UnorderedStringMap`:  Specialized unordered set and map using the custom hash/equality functions, likely optimized for V8's memory management (using `ZoneAllocator`). These confirm the storage of sets of strings and mappings from strings to objects.
    * `Module::ResolveSet`:  Used for tracking module resolution to detect cycles. The nested `UnorderedStringSet` suggests tracking names within a module during resolution.
    * `SourceTextModule::AsyncEvaluationOrdinalCompare`:  Used for sorting modules based on their asynchronous evaluation order.
* **Key Functions (and their roles):**
    * `GetSharedFunctionInfo()`, `GetScript()`: Retrieve metadata associated with the module's code.
    * `ExportIndex()`, `ImportIndex()`:  Mapping logical export/import indices to internal array indices.
    * `CreateIndirectExport()`, `CreateExport()`:  Populating the module's export table.
    * `GetCell()`:  Accessing the storage location (Cell) for a module variable.
    * `LoadVariable()`, `StoreVariable()`:  Getting and setting the values of exported variables.
    * `ResolveExport()`, `ResolveImport()`:  The core logic for resolving import and export relationships between modules, including cycle detection.
    * `ResolveExportUsingStarExports()`: Handling `export * from ...`.
    * `PrepareInstantiate()`:  The initial phase of module loading, involving fetching dependencies.
    * `RunInitializationCode()`:  Executing the module's top-level code.
    * `MaybeTransitionComponent()`:  Managing the state transitions of modules during linking and evaluation, especially for detecting and handling cycles.
    * `FinishInstantiate()`:  The second phase of module loading, performing linking and import resolution.
    * `FetchStarExports()`:  Populating the export table with exports from re-exported modules.
    * `GatherAvailableAncestors()`:  Related to asynchronous module evaluation.
    * `GetModuleNamespace()`:  Retrieving the module's namespace object.
    * `GetImportMeta()`:  Handling the `import.meta` object.
    * `MaybeHandleEvaluationException()`:  Dealing with exceptions during module evaluation.

**4. Answering the Specific Questions:**

* **Functionality:**  Based on the above analysis, summarize the core functions.
* **Torque:** Explicitly check the file extension.
* **JavaScript Relationship:** Identify functions that directly correspond to JavaScript module features (imports, exports, `import.meta`, execution). Provide simple JavaScript examples.
* **Code Logic Inference:** Choose a function like `ResolveExport` or `FinishInstantiate` and describe a simple scenario with hypothetical inputs and expected outputs.
* **Common Programming Errors:**  Relate the V8 code to potential errors JavaScript developers might make (e.g., cyclic dependencies, unresolved exports).
* **Summary:**  Synthesize the findings into a concise summary of the file's purpose.

**5. Refinement and Organization:**

* Group related functionalities together.
* Use clear and concise language.
* Provide code snippets and examples where appropriate.
* Structure the answer logically, following the order of the questions.

This structured approach, moving from high-level understanding to detailed analysis of key components, allows for a comprehensive and accurate explanation of the `source-text-module.cc` file's functionality within the V8 engine. The iterative refinement, where initial hypotheses are tested and adjusted based on code examination, is crucial for this process.
```cpp
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/objects/source-text-module.h"

#include "src/api/api-inl.h"
#include "src/ast/modules.h"
#include "src/builtins/accessors.h"
#include "src/common/assert-scope.h"
#include "src/objects/js-generator-inl.h"
#include "src/objects/module-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/shared-function-info.h"
#include "src/utils/ostreams.h"

namespace v8 {
namespace internal {

struct StringHandleHash {
  V8_INLINE size_t operator()(DirectHandle<String> string) const {
    return string->EnsureHash();
  }
};

struct StringHandleEqual {
  V8_INLINE bool operator()(DirectHandle<String> lhs,
                            DirectHandle<String> rhs) const {
    return lhs->Equals(*rhs);
  }
};

class UnorderedStringSet
    : public std::unordered_set<Handle<String>, StringHandleHash,
                                StringHandleEqual,
                                ZoneAllocator<Handle<String>>> {
 public:
  explicit UnorderedStringSet(Zone* zone)
      : std::unordered_set<Handle<String>, StringHandleHash, StringHandleEqual,
                           ZoneAllocator<Handle<String>>>(
            2 /* bucket count */, StringHandleHash(), StringHandleEqual(),
            ZoneAllocator<Handle<String>>(zone)) {}
};

class UnorderedStringMap
    : public std::unordered_map<
          Handle<String>, Handle<Object>, StringHandleHash, StringHandleEqual,
          ZoneAllocator<std::pair<const Handle<String>, Handle<Object>>>> {
 public:
  explicit UnorderedStringMap(Zone* zone)
      : std::unordered_map<
            Handle<String>, Handle<Object>, StringHandleHash, StringHandleEqual,
            ZoneAllocator<std::pair<const Handle<String>, Handle<Object>>>>(
            2 /* bucket count */, StringHandleHash(), StringHandleEqual(),
            ZoneAllocator<std::pair<const Handle<String>, Handle<Object>>>(
                zone)) {}
};

class Module::ResolveSet
    : public std::unordered_map<
          Handle<Module>, UnorderedStringSet*, ModuleHandleHash,
          ModuleHandleEqual,
          ZoneAllocator<std::pair<const Handle<Module>, UnorderedStringSet*>>> {
 public:
  explicit ResolveSet(Zone* zone)
      : std::unordered_map<Handle<Module>, UnorderedStringSet*,
                           ModuleHandleHash, ModuleHandleEqual,
                           ZoneAllocator<std::pair<const Handle<Module>,
                                                   UnorderedStringSet*>>>(
            2 /* bucket count */, ModuleHandleHash(), ModuleHandleEqual(),
            ZoneAllocator<std::pair<const Handle<Module>, UnorderedStringSet*>>(
                zone)),
        zone_(zone) {}

  Zone* zone() const { return zone_; }

 private:
  Zone* zone_;
};

struct SourceTextModule::AsyncEvaluationOrdinalCompare {
  bool operator()(DirectHandle<SourceTextModule> lhs,
                  DirectHandle<SourceTextModule> rhs) const {
    DCHECK(lhs->HasAsyncEvaluationOrdinal());
    DCHECK(rhs->HasAsyncEvaluationOrdinal());
    return lhs->async_evaluation_ordinal() < rhs->async_evaluation_ordinal();
  }
};

Tagged<SharedFunctionInfo> SourceTextModule::GetSharedFunctionInfo() const {
  DisallowGarbageCollection no_gc;
  switch (status()) {
    case kUnlinked:
    case kPreLinking:
      return Cast<SharedFunctionInfo>(code());
    case kLinking:
      return Cast<JSFunction>(code())->shared();
    case kLinked:
    case kEvaluating:
    case kEvaluatingAsync:
    case kEvaluated:
      return Cast<JSGeneratorObject>(code())->function()->shared();
    case kErrored:
      return Cast<SharedFunctionInfo>(code());
  }
  UNREACHABLE();
}

Tagged<Script> SourceTextModule::GetScript() const {
  DisallowGarbageCollection no_gc;
  return Cast<Script>(GetSharedFunctionInfo()->script());
}

int SourceTextModule::ExportIndex(int cell_index) {
  DCHECK_EQ(SourceTextModuleDescriptor::GetCellIndexKind(cell_index),
            SourceTextModuleDescriptor::kExport);
  return cell_index - 1;
}

int SourceTextModule::ImportIndex(int cell_index) {
  DCHECK_EQ(SourceTextModuleDescriptor::GetCellIndexKind(cell_index),
            SourceTextModuleDescriptor::kImport);
  return -cell_index - 1;
}

void SourceTextModule::CreateIndirectExport(
    Isolate* isolate, DirectHandle<SourceTextModule> module,
    Handle<String> name, Handle<SourceTextModuleInfoEntry> entry) {
  Handle<ObjectHashTable> exports(module->exports(), isolate);
  DCHECK(IsTheHole(exports->Lookup(name), isolate));
  exports = ObjectHashTable::Put(exports, name, entry);
  module->set_exports(*exports);
}

void SourceTextModule::CreateExport(Isolate* isolate,
                                    DirectHandle<SourceTextModule> module,
                                    int cell_index,
                                    DirectHandle<FixedArray> names) {
  DCHECK_LT(0, names->length());
  Handle<Cell> cell = isolate->factory()->NewCell();
  module->regular_exports()->set(ExportIndex(cell_index), *cell);

  Handle<ObjectHashTable> exports(module->exports(), isolate);
  for (int i = 0, n = names->length(); i < n; ++i) {
    Handle<String> name(Cast<String>(names->get(i)), isolate);
    DCHECK(IsTheHole(exports->Lookup(name), isolate));
    exports = ObjectHashTable::Put(exports, name, cell);
  }
  module->set_exports(*exports);
}

Tagged<Cell> SourceTextModule::GetCell(int cell_index) {
  DisallowGarbageCollection no_gc;
  Tagged<Object> cell;
  switch (SourceTextModuleDescriptor::GetCellIndexKind(cell_index)) {
    case SourceTextModuleDescriptor::kImport:
      cell = regular_imports()->get(ImportIndex(cell_index));
      break;
    case SourceTextModuleDescriptor::kExport:
      cell = regular_exports()->get(ExportIndex(cell_index));
      break;
    case SourceTextModuleDescriptor::kInvalid:
      UNREACHABLE();
  }
  return Cast<Cell>(cell);
}

Handle<Object> SourceTextModule::LoadVariable(
    Isolate* isolate, DirectHandle<SourceTextModule> module, int cell_index) {
  return handle(module->GetCell(cell_index)->value(), isolate);
}

void SourceTextModule::StoreVariable(DirectHandle<SourceTextModule> module,
                                     int cell_index,
                                     DirectHandle<Object> value) {
  DisallowGarbageCollection no_gc;
  DCHECK_EQ(SourceTextModuleDescriptor::GetCellIndexKind(cell_index),
            SourceTextModuleDescriptor::kExport);
  module->GetCell(cell_index)->set_value(*value);
}

MaybeHandle<Cell> SourceTextModule::ResolveExport(
    Isolate* isolate, Handle<SourceTextModule> module,
    Handle<String> module_specifier, Handle<String> export_name,
    MessageLocation loc, bool must_resolve, Module::ResolveSet* resolve_set) {
  Handle<Object> object(module->exports()->Lookup(export_name), isolate);
  if (IsCell(*object)) {
    // Already resolved (e.g. because it's a local export).
    return Cast<Cell>(object);
  }

  // Check for cycle before recursing.
  {
    // Attempt insertion with a null string set.
    auto result = resolve_set->insert({module, nullptr});
    UnorderedStringSet*& name_set = result.first->second;
    if (result.second) {
      // |module| wasn't in the map previously, so allocate a new name set.
      Zone* zone = resolve_set->zone();
      name_set = zone->New<UnorderedStringSet>(zone);
    } else if (name_set->count(export_name)) {
      // Cycle detected.
      if (must_resolve) {
        isolate->ThrowAt(isolate->factory()->NewSyntaxError(
                             MessageTemplate::kCyclicModuleDependency,
                             export_name, module_specifier),
                         &loc);
        return MaybeHandle<Cell>();
      }
      return MaybeHandle<Cell>();
    }
    name_set->insert(export_name);
  }

  if (IsSourceTextModuleInfoEntry(*object)) {
    // Not yet resolved indirect export.
    auto entry = Cast<SourceTextModuleInfoEntry>(object);
    Handle<String> import_name(Cast<String>(entry->import_name()), isolate);
    Handle<Script> script(module->GetScript(), isolate);
    MessageLocation new_loc(script, entry->beg_pos(), entry->end_pos());

    Handle<Cell> cell;
    if (!ResolveImport(isolate, module, import_name, entry->module_request(),
                       new_loc, true, resolve_set)
             .ToHandle(&cell)) {
      DCHECK(isolate->has_exception());
      return MaybeHandle<Cell>();
    }

    // The export table may have changed but the entry in question should be
    // unchanged.
    Handle<ObjectHashTable> exports(module->exports(), isolate);
    DCHECK(IsSourceTextModuleInfoEntry(exports->Lookup(export_name)));

    exports = ObjectHashTable::Put(exports, export_name, cell);
    module->set_exports(*exports);
    return cell;
  }

  DCHECK(IsTheHole(*object, isolate));
  return SourceTextModule::ResolveExportUsingStarExports(
      isolate, module, module_specifier, export_name, loc, must_resolve,
      resolve_set);
}

MaybeHandle<Cell> SourceTextModule::ResolveImport(
    Isolate* isolate, DirectHandle<SourceTextModule> module,
    Handle<String> name, int module_request_index, MessageLocation loc,
    bool must_resolve, Module::ResolveSet* resolve_set) {
  DirectHandle<ModuleRequest> module_request(
      Cast<ModuleRequest>(
          module->info()->module_requests()->get(module_request_index)),
      isolate);
  switch (module_request->phase()) {
    case ModuleImportPhase::kSource: {
      DCHECK(v8_flags.js_source_phase_imports);

      // https://tc39.es/proposal-source-phase-imports/#sec-source-text-module-record-initialize-environment
      // InitializeEnvironment
      // 7.c. Else if in.[[ImportName]] is source, then
      // 7.c.i. Let moduleSourceObject be ? importedModule.GetModuleSource().
      // 7.c.ii. Perform ! env.CreateImmutableBinding(in.[[LocalName]], true).
      // 7.c.iii. Perform ! env.InitializeBinding(in.[[LocalName]],
      //          moduleSourceObject).
      Handle<Cell> cell = isolate->factory()->NewCell();
      cell->set_value(module->requested_modules()->get(module_request_index));
      return cell;
    }
    case ModuleImportPhase::kEvaluation: {
      DCHECK_EQ(module_request->phase(), ModuleImportPhase::kEvaluation);
      Handle<Module> requested_module(
          Cast<Module>(module->requested_modules()->get(module_request_index)),
          isolate);
      Handle<String> module_specifier(Cast<String>(module_request->specifier()),
                                      isolate);
      MaybeHandle<Cell> result =
          Module::ResolveExport(isolate, requested_module, module_specifier,
                                name, loc, must_resolve, resolve_set);
      DCHECK_IMPLIES(isolate->has_exception(), result.is_null());
      return result;
    }
    default:
      UNREACHABLE();
  }
}

MaybeHandle<Cell> SourceTextModule::ResolveExportUsingStarExports(
    Isolate* isolate, DirectHandle<SourceTextModule> module,
    Handle<String> module_specifier, Handle<String> export_name,
    MessageLocation loc, bool must_resolve, Module::ResolveSet* resolve_set) {
  if (!export_name->Equals(ReadOnlyRoots(isolate).default_string())) {
    // Go through all star exports looking for the given name. If multiple star
    // exports provide the name, make sure they all map it to the same cell.
    Handle<Cell> unique_cell;
    DirectHandle<FixedArray> special_exports(module->info()->special_exports(),
                                             isolate);
    for (int i = 0, n = special_exports->length(); i < n; ++i) {
      i::DirectHandle<i::SourceTextModuleInfoEntry> entry(
          i::Cast<i::SourceTextModuleInfoEntry>(special_exports->get(i)),
          isolate);
      if (!IsUndefined(entry->export_name(), isolate)) {
        continue;  // Indirect export.
      }

      Handle<Script> script(module->GetScript(), isolate);
      MessageLocation new_loc(script, entry->beg_pos(), entry->end_pos());

      Handle<Cell> cell;
      if (ResolveImport(isolate, module, export_name, entry->module_request(),
                        new_loc, false, resolve_set)
              .ToHandle(&cell)) {
        if (unique_cell.is_null()) unique_cell = cell;
        if (*unique_cell != *cell) {
          isolate->ThrowAt(isolate->factory()->NewSyntaxError(
                               MessageTemplate::kAmbiguousExport,
                               module_specifier, export_name),
                           &loc);
          return MaybeHandle<Cell>();
        }
      } else if (isolate->has_exception()) {
        return MaybeHandle<Cell>();
      }
    }

    if (!unique_cell.is_null()) {
      // Found a unique star export for this name.
      Handle<ObjectHashTable> exports(module->exports(), isolate);
      DCHECK(IsTheHole(exports->Lookup(export_name), isolate));
      exports = ObjectHashTable::Put(exports, export_name, unique_cell);
      module->set_exports(*exports);
      return unique_cell;
    }
  }

  // Unresolvable.
  if (must_resolve) {
    isolate->ThrowAt(
        isolate->factory()->NewSyntaxError(MessageTemplate::kUnresolvableExport,
                                           module_specifier, export_name),
        &loc);
    return MaybeHandle<Cell>();
  }
  return MaybeHandle<Cell>();
}

bool SourceTextModule::PrepareInstantiate(
    Isolate* isolate, Handle<SourceTextModule> module,
    v8::Local<v8::Context> context,
    v8::Module::ResolveModuleCallback module_callback,
    v8::Module::ResolveSourceCallback source_callback) {
  DCHECK_NE(module_callback, nullptr);
  // Obtain requested modules.
  DirectHandle<SourceTextModuleInfo> module_info(module->info(), isolate);
  DirectHandle<FixedArray> module_requests(module_info->module_requests(),
                                           isolate);
  DirectHandle<FixedArray> requested_modules(module->requested_modules(),
                                             isolate);
  for (int i = 0, length = module_requests->length(); i < length; ++i) {
    DirectHandle<ModuleRequest> module_request(
        Cast<ModuleRequest>(module_requests->get(i)), isolate);
    Handle<String> specifier(module_request->specifier(), isolate);
    Handle<FixedArray> import_attributes(module_request->import_attributes(),
                                         isolate);
    switch (module_request->phase()) {
      case ModuleImportPhase::kEvaluation: {
        v8::Local<v8::Module> api_requested_module;
        if (!module_callback(context, v8::Utils::ToLocal(specifier),
                             v8::Utils::FixedArrayToLocal(import_attributes),
                             v8::Utils::ToLocal(Cast<Module>(module)))
                 .ToLocal(&api_requested_module)) {
          return false;
        }
        DirectHandle<Module> requested_module =
            Utils::OpenDirectHandle(*api_requested_module);
        requested_modules->set(i, *requested_module);
        break;
      }
      case ModuleImportPhase::kSource: {
        DCHECK(v8_flags.js_source_phase_imports);
#if V8_ENABLE_WEBASSEMBLY
        v8::Local<v8::Object> api_requested_module_source;
        if (!source_callback(context, v8::Utils::ToLocal(specifier),
                             v8::Utils::FixedArrayToLocal(import_attributes),
                             v8::Utils::ToLocal(Cast<Module>(module)))
                 .ToLocal(&api_requested_module_source)) {
          return false;
        }
        DirectHandle<JSReceiver> requested_module_source =
            Utils::OpenDirectHandle(*api_requested_module_source);
        CHECK(IsWasmModuleObject(*requested_module_source));
        requested_modules->set(i, *requested_module_source);
        break;
#else
        // Only WebAssembly modules can be requested in the source phase.
        UNREACHABLE();
#endif
      }
      default:
        UNREACHABLE();
    }
  }

  // Recurse.
  for (int i = 0, length = requested_modules->length(); i < length; ++i) {
    DirectHandle<ModuleRequest> module_request(
        Cast<ModuleRequest>(module_requests->get(i)), isolate);
    if (module_request->phase() != ModuleImportPhase::kEvaluation) {
      continue;
    }
    Handle<Module> requested_module(Cast<Module>(requested_modules->get(i)),
                                    isolate);
    if (!Module::PrepareInstantiate(isolate, requested_module, context,
                                    module_callback, source_callback)) {
      return false;
    }
  }

  // Set up local exports.
  // TODO(neis): Create regular_exports array here instead of in factory method?
  for (int i = 0, n = module_info->RegularExportCount(); i < n; ++i) {
    int cell_index = module_info->RegularExportCellIndex(i);
    DirectHandle<FixedArray> export_names(
        module_info->RegularExportExportNames(i), isolate);
    CreateExport(isolate, module, cell_index, export_names);
  }

  // Partially set up indirect exports.
  // For each indirect export, we create the appropriate slot in the export
  // table and store its SourceTextModuleInfoEntry there. When we later find
  // the correct Cell in the module that actually provides the value, we replace
  // the SourceTextModuleInfoEntry by that Cell (see ResolveExport).
  DirectHandle<FixedArray> special_exports(module_info->special_exports(),
                                           isolate);
  for (int i = 0, n = special_exports->length(); i < n; ++i) {
    Handle<SourceTextModuleInfoEntry> entry(
        Cast<SourceTextModuleInfoEntry>(special_exports->get(i)), isolate);
    Handle<Object> export_name(entry->export_name(), isolate);
    if (IsUndefined(*export_name, isolate)) continue;  // Star export.
    CreateIndirectExport(isolate, module, Cast<String>(export_name), entry);
  }

  DCHECK_EQ(module->status(), kPreLinking);
  return true;
}

bool SourceTextModule::RunInitializationCode(
    Isolate* isolate, DirectHandle<SourceTextModule> module) {
  DCHECK_EQ(module->status(), kLinking);
  Handle<JSFunction> function(Cast<JSFunction>(module->code()), isolate);
  DCHECK_EQ(MODULE_SCOPE, function->shared()->scope_info()->scope_type());
  Handle<Object> receiver = isolate->factory()->undefined_value();

  DirectHandle<ScopeInfo> scope_info(function->shared()->scope_info(), isolate);
  DirectHandle<Context> context = isolate->factory()->NewModuleContext(
      module, isolate->native_context(), scope_info);
  function->set_context(*context);

  MaybeHandle<Object> maybe_generator =
      Execution::Call(isolate, function, receiver, 0, {});
  Handle<Object> generator;
  if (!maybe_generator.ToHandle(&generator)) {
    DCHECK(isolate->has_exception());
    return false;
  }
  DCHECK_EQ(*function, Cast<JSGeneratorObject>(generator)->function());
  module->set_code(Cast<JSGeneratorObject>(*generator));
  return true;
}

// ES#sec-innermoduleevaluation and ES#sec-innermodulelinking
bool SourceTextModule::MaybeTransitionComponent(
    Isolate* isolate, DirectHandle<SourceTextModule> module,
    ZoneForwardList<Handle<SourceTextModule>>* stack, Status new_status) {
  DCHECK(new_status == kLinked || new_status == kEvaluated);

#ifdef DEBUG
  if (v8_flags.trace_module_status) {
    StdoutStream os;
    os << "Transitioning strongly connected module graph component to "
       << Module::StatusString(new_status) << " {\n";
  }
#endif  // DEBUG

  // Below, N/M means step N in InnerModuleEvaluation and step M in
  // InnerModuleLinking.

  // 14/11. Assert: module occurs exactly once in stack.
  SLOW_DCHECK(
      // {module} is on the {stack}.
      std::count_if(stack->begin(), stack->end(), [&](DirectHandle<Module> m) {
        return *m == *module;
      }) == 1);

  // 15/12. Assert: module.[[DFSAncestorIndex]] ≤ module.[[DFSIndex]].
  DCHECK_LE(module->dfs_ancestor_index(), module->dfs_index());

  // 16/13. If module.[[DFSAncestorIndex]] = module.[[DFSIndex]], then
  if (module->dfs_ancestor_index() == module->dfs_index()) {
    // This is the root of its strongly connected component.
    DirectHandle<SourceTextModule> cycle_root = module;
    DirectHandle<SourceTextModule> ancestor;
    // This loop handles the loops in both InnerModuleEvaluation and
    // InnerModuleLinking.
    //
    // InnerModuleEvaluation
    //
    // a. Let done be false.
    // b. Repeat, while done is false,
    //     i. Let requiredModule be the last element of stack.
    //    ii. Remove the last element of stack.
    //   iii. Assert: requiredModule is a Cyclic Module Record.
    //    iv. If requiredModule.[[AsyncEvaluation]] is false, set
    //        requiredModule.[[Status]] to EVALUATED.
    //     v. Otherwise, set requiredModule.[[Status]] to EVALUATING-ASYNC.
    //    vi. If requiredModule and module are the same Module Record, set done
    //        to true.
    //   vii. Set requiredModule.[[CycleRoot]] to module.
    //
    // InnerModuleLinking
    //
    // a. Let done be false.
    // b. Repeat, while done is false,
    //     i. Let requiredModule be the last element of stack.
    //    ii. Remove the last element of stack.
    //   iii. Assert: requiredModule is a Cyclic Module Record.
    //    iv. Set requiredModule.[[Status]] to LINKED.
    //     v. If requiredModule and module are the same Module Record, set done
    //        to true.
    do {
      ancestor = stack->front();
      stack->pop_front();
      DCHECK_EQ(ancestor->status(),
                new_status == kLinked ? kLinking : kEvaluating);
      if (new_status == kLinked) {
        if (!SourceTextModule::RunInitializationCode(isolate, ancestor)) {
          return false;
        }
        ancestor->SetStatus(kLinked);
      } else {
        DCHECK(IsTheHole(ancestor->cycle_root(), isolate));
        ancestor->set_cycle_root(*cycle_root);
        ancestor->SetStatus(ancestor->HasAsyncEvaluationOrdinal()
                                ? kEvaluatingAsync
                                : kEvaluated);
      }
    } while (*ancestor != *module);
  }
#ifdef DEBUG
  if (v8_flags.trace_module_status) {
    StdoutStream os;
    os << "}\n";
  }
#endif  // DEBUG
  return true;
}

bool SourceTextModule::FinishInstantiate(
    Isolate* isolate, Handle<SourceTextModule> module,
    ZoneForwardList<Handle<SourceTextModule>>* stack, unsigned* dfs_index,
    Zone* zone) {
  // Instantiate SharedFunctionInfo and mark module as instantiating for
  // the recursion.
  Handle<SharedFunctionInfo> shared(Cast<SharedFunctionInfo>(module->code()),
                                    isolate);
  DirectHandle<JSFunction> function =
      Factory::JSFunctionBuilder{isolate, shared, isolate->native_context()}
          .Build();
  module->set_code(*function);
  module->SetStatus(kLinking);
  module->set_dfs_index(*dfs_index);
  module->set_dfs_ancestor_index(*dfs_index);
  stack->push_front(module);
  (*dfs_index)++;

  // Recurse.
  DirectHandle<FixedArray> module_requests(module->info()->module_requests(),
                                           isolate);
  DirectHandle<FixedArray> requested_modules(module->requested_modules(),
                                             isolate);
  for (int i = 0, length = requested_modules->length(); i < length; ++i) {
    DirectHandle<ModuleRequest> module_request(
        Cast<ModuleRequest>(module_requests->get(i)), isolate);
    if (module_request->phase() != ModuleImportPhase::kEvaluation) {
      continue;
    }
    Handle<Module> requested_module(Cast<Module>(requested_modules->get(i)),
                                    isolate);
    if (!Module::FinishInstantiate(isolate, requested_module, stack, dfs_index,
                                   zone)) {
      return false;
    }

    DCHECK_NE(requested_module->status(), kEvaluating);
    DCHECK_GE(requested_module->status(), kLinking);
    SLOW_DCHECK(
        // {requested_module} is instantiating iff it's on the {stack}.
        (requested_module->status() == kLinking) ==
        std::count_if(
            stack->begin(), stack->end(),
            [&](DirectHandle<Module> m) { return *m == *requested_module; }));

    if (requested_module->status() == kLinking) {
      // SyntheticModules go straight to kLinked so this must be a
      // SourceTextModule
      module->set_dfs_ancestor_index(std::min(
          module->dfs_ancestor_index(),
          Cast<SourceTextModule>(*requested_module)->dfs_ancestor_index()));
    }
  }

  Handle<Script> script(module->GetScript(), isolate);
  DirectHandle<SourceTextModuleInfo> module_info(module->info(), isolate);

  // Resolve imports.
  DirectHandle<FixedArray> regular_imports(module_info->regular_imports(),
                                           isolate);
  for (int i = 0, n = regular_imports->length(); i < n; ++i) {
    DirectHandle<SourceTextModuleInfoEntry> entry(
        Cast<SourceTextModuleInfoEntry>(regular_imports->get(i)), isolate);
    Handle<String> name(Cast<String>(entry->import_name()), isolate);
    MessageLocation loc(script, entry->beg_pos(), entry->end_pos());
    ResolveSet resolve_set(zone);
    Handle<Cell> cell;
    if (!ResolveImport(isolate, module, name, entry->module_request(), loc,
                       true, &resolve_set)
             .ToHandle(&cell)) {
      return false;
    }
### 提示词
```
这是目录为v8/src/objects/source-text-module.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/source-text-module.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/objects/source-text-module.h"

#include "src/api/api-inl.h"
#include "src/ast/modules.h"
#include "src/builtins/accessors.h"
#include "src/common/assert-scope.h"
#include "src/objects/js-generator-inl.h"
#include "src/objects/module-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/shared-function-info.h"
#include "src/utils/ostreams.h"

namespace v8 {
namespace internal {

struct StringHandleHash {
  V8_INLINE size_t operator()(DirectHandle<String> string) const {
    return string->EnsureHash();
  }
};

struct StringHandleEqual {
  V8_INLINE bool operator()(DirectHandle<String> lhs,
                            DirectHandle<String> rhs) const {
    return lhs->Equals(*rhs);
  }
};

class UnorderedStringSet
    : public std::unordered_set<Handle<String>, StringHandleHash,
                                StringHandleEqual,
                                ZoneAllocator<Handle<String>>> {
 public:
  explicit UnorderedStringSet(Zone* zone)
      : std::unordered_set<Handle<String>, StringHandleHash, StringHandleEqual,
                           ZoneAllocator<Handle<String>>>(
            2 /* bucket count */, StringHandleHash(), StringHandleEqual(),
            ZoneAllocator<Handle<String>>(zone)) {}
};

class UnorderedStringMap
    : public std::unordered_map<
          Handle<String>, Handle<Object>, StringHandleHash, StringHandleEqual,
          ZoneAllocator<std::pair<const Handle<String>, Handle<Object>>>> {
 public:
  explicit UnorderedStringMap(Zone* zone)
      : std::unordered_map<
            Handle<String>, Handle<Object>, StringHandleHash, StringHandleEqual,
            ZoneAllocator<std::pair<const Handle<String>, Handle<Object>>>>(
            2 /* bucket count */, StringHandleHash(), StringHandleEqual(),
            ZoneAllocator<std::pair<const Handle<String>, Handle<Object>>>(
                zone)) {}
};

class Module::ResolveSet
    : public std::unordered_map<
          Handle<Module>, UnorderedStringSet*, ModuleHandleHash,
          ModuleHandleEqual,
          ZoneAllocator<std::pair<const Handle<Module>, UnorderedStringSet*>>> {
 public:
  explicit ResolveSet(Zone* zone)
      : std::unordered_map<Handle<Module>, UnorderedStringSet*,
                           ModuleHandleHash, ModuleHandleEqual,
                           ZoneAllocator<std::pair<const Handle<Module>,
                                                   UnorderedStringSet*>>>(
            2 /* bucket count */, ModuleHandleHash(), ModuleHandleEqual(),
            ZoneAllocator<std::pair<const Handle<Module>, UnorderedStringSet*>>(
                zone)),
        zone_(zone) {}

  Zone* zone() const { return zone_; }

 private:
  Zone* zone_;
};

struct SourceTextModule::AsyncEvaluationOrdinalCompare {
  bool operator()(DirectHandle<SourceTextModule> lhs,
                  DirectHandle<SourceTextModule> rhs) const {
    DCHECK(lhs->HasAsyncEvaluationOrdinal());
    DCHECK(rhs->HasAsyncEvaluationOrdinal());
    return lhs->async_evaluation_ordinal() < rhs->async_evaluation_ordinal();
  }
};

Tagged<SharedFunctionInfo> SourceTextModule::GetSharedFunctionInfo() const {
  DisallowGarbageCollection no_gc;
  switch (status()) {
    case kUnlinked:
    case kPreLinking:
      return Cast<SharedFunctionInfo>(code());
    case kLinking:
      return Cast<JSFunction>(code())->shared();
    case kLinked:
    case kEvaluating:
    case kEvaluatingAsync:
    case kEvaluated:
      return Cast<JSGeneratorObject>(code())->function()->shared();
    case kErrored:
      return Cast<SharedFunctionInfo>(code());
  }
  UNREACHABLE();
}

Tagged<Script> SourceTextModule::GetScript() const {
  DisallowGarbageCollection no_gc;
  return Cast<Script>(GetSharedFunctionInfo()->script());
}

int SourceTextModule::ExportIndex(int cell_index) {
  DCHECK_EQ(SourceTextModuleDescriptor::GetCellIndexKind(cell_index),
            SourceTextModuleDescriptor::kExport);
  return cell_index - 1;
}

int SourceTextModule::ImportIndex(int cell_index) {
  DCHECK_EQ(SourceTextModuleDescriptor::GetCellIndexKind(cell_index),
            SourceTextModuleDescriptor::kImport);
  return -cell_index - 1;
}

void SourceTextModule::CreateIndirectExport(
    Isolate* isolate, DirectHandle<SourceTextModule> module,
    Handle<String> name, Handle<SourceTextModuleInfoEntry> entry) {
  Handle<ObjectHashTable> exports(module->exports(), isolate);
  DCHECK(IsTheHole(exports->Lookup(name), isolate));
  exports = ObjectHashTable::Put(exports, name, entry);
  module->set_exports(*exports);
}

void SourceTextModule::CreateExport(Isolate* isolate,
                                    DirectHandle<SourceTextModule> module,
                                    int cell_index,
                                    DirectHandle<FixedArray> names) {
  DCHECK_LT(0, names->length());
  Handle<Cell> cell = isolate->factory()->NewCell();
  module->regular_exports()->set(ExportIndex(cell_index), *cell);

  Handle<ObjectHashTable> exports(module->exports(), isolate);
  for (int i = 0, n = names->length(); i < n; ++i) {
    Handle<String> name(Cast<String>(names->get(i)), isolate);
    DCHECK(IsTheHole(exports->Lookup(name), isolate));
    exports = ObjectHashTable::Put(exports, name, cell);
  }
  module->set_exports(*exports);
}

Tagged<Cell> SourceTextModule::GetCell(int cell_index) {
  DisallowGarbageCollection no_gc;
  Tagged<Object> cell;
  switch (SourceTextModuleDescriptor::GetCellIndexKind(cell_index)) {
    case SourceTextModuleDescriptor::kImport:
      cell = regular_imports()->get(ImportIndex(cell_index));
      break;
    case SourceTextModuleDescriptor::kExport:
      cell = regular_exports()->get(ExportIndex(cell_index));
      break;
    case SourceTextModuleDescriptor::kInvalid:
      UNREACHABLE();
  }
  return Cast<Cell>(cell);
}

Handle<Object> SourceTextModule::LoadVariable(
    Isolate* isolate, DirectHandle<SourceTextModule> module, int cell_index) {
  return handle(module->GetCell(cell_index)->value(), isolate);
}

void SourceTextModule::StoreVariable(DirectHandle<SourceTextModule> module,
                                     int cell_index,
                                     DirectHandle<Object> value) {
  DisallowGarbageCollection no_gc;
  DCHECK_EQ(SourceTextModuleDescriptor::GetCellIndexKind(cell_index),
            SourceTextModuleDescriptor::kExport);
  module->GetCell(cell_index)->set_value(*value);
}

MaybeHandle<Cell> SourceTextModule::ResolveExport(
    Isolate* isolate, Handle<SourceTextModule> module,
    Handle<String> module_specifier, Handle<String> export_name,
    MessageLocation loc, bool must_resolve, Module::ResolveSet* resolve_set) {
  Handle<Object> object(module->exports()->Lookup(export_name), isolate);
  if (IsCell(*object)) {
    // Already resolved (e.g. because it's a local export).
    return Cast<Cell>(object);
  }

  // Check for cycle before recursing.
  {
    // Attempt insertion with a null string set.
    auto result = resolve_set->insert({module, nullptr});
    UnorderedStringSet*& name_set = result.first->second;
    if (result.second) {
      // |module| wasn't in the map previously, so allocate a new name set.
      Zone* zone = resolve_set->zone();
      name_set = zone->New<UnorderedStringSet>(zone);
    } else if (name_set->count(export_name)) {
      // Cycle detected.
      if (must_resolve) {
        isolate->ThrowAt(isolate->factory()->NewSyntaxError(
                             MessageTemplate::kCyclicModuleDependency,
                             export_name, module_specifier),
                         &loc);
        return MaybeHandle<Cell>();
      }
      return MaybeHandle<Cell>();
    }
    name_set->insert(export_name);
  }

  if (IsSourceTextModuleInfoEntry(*object)) {
    // Not yet resolved indirect export.
    auto entry = Cast<SourceTextModuleInfoEntry>(object);
    Handle<String> import_name(Cast<String>(entry->import_name()), isolate);
    Handle<Script> script(module->GetScript(), isolate);
    MessageLocation new_loc(script, entry->beg_pos(), entry->end_pos());

    Handle<Cell> cell;
    if (!ResolveImport(isolate, module, import_name, entry->module_request(),
                       new_loc, true, resolve_set)
             .ToHandle(&cell)) {
      DCHECK(isolate->has_exception());
      return MaybeHandle<Cell>();
    }

    // The export table may have changed but the entry in question should be
    // unchanged.
    Handle<ObjectHashTable> exports(module->exports(), isolate);
    DCHECK(IsSourceTextModuleInfoEntry(exports->Lookup(export_name)));

    exports = ObjectHashTable::Put(exports, export_name, cell);
    module->set_exports(*exports);
    return cell;
  }

  DCHECK(IsTheHole(*object, isolate));
  return SourceTextModule::ResolveExportUsingStarExports(
      isolate, module, module_specifier, export_name, loc, must_resolve,
      resolve_set);
}

MaybeHandle<Cell> SourceTextModule::ResolveImport(
    Isolate* isolate, DirectHandle<SourceTextModule> module,
    Handle<String> name, int module_request_index, MessageLocation loc,
    bool must_resolve, Module::ResolveSet* resolve_set) {
  DirectHandle<ModuleRequest> module_request(
      Cast<ModuleRequest>(
          module->info()->module_requests()->get(module_request_index)),
      isolate);
  switch (module_request->phase()) {
    case ModuleImportPhase::kSource: {
      DCHECK(v8_flags.js_source_phase_imports);

      // https://tc39.es/proposal-source-phase-imports/#sec-source-text-module-record-initialize-environment
      // InitializeEnvironment
      // 7.c. Else if in.[[ImportName]] is source, then
      // 7.c.i. Let moduleSourceObject be ? importedModule.GetModuleSource().
      // 7.c.ii. Perform ! env.CreateImmutableBinding(in.[[LocalName]], true).
      // 7.c.iii. Perform ! env.InitializeBinding(in.[[LocalName]],
      //          moduleSourceObject).
      Handle<Cell> cell = isolate->factory()->NewCell();
      cell->set_value(module->requested_modules()->get(module_request_index));
      return cell;
    }
    case ModuleImportPhase::kEvaluation: {
      DCHECK_EQ(module_request->phase(), ModuleImportPhase::kEvaluation);
      Handle<Module> requested_module(
          Cast<Module>(module->requested_modules()->get(module_request_index)),
          isolate);
      Handle<String> module_specifier(Cast<String>(module_request->specifier()),
                                      isolate);
      MaybeHandle<Cell> result =
          Module::ResolveExport(isolate, requested_module, module_specifier,
                                name, loc, must_resolve, resolve_set);
      DCHECK_IMPLIES(isolate->has_exception(), result.is_null());
      return result;
    }
    default:
      UNREACHABLE();
  }
}

MaybeHandle<Cell> SourceTextModule::ResolveExportUsingStarExports(
    Isolate* isolate, DirectHandle<SourceTextModule> module,
    Handle<String> module_specifier, Handle<String> export_name,
    MessageLocation loc, bool must_resolve, Module::ResolveSet* resolve_set) {
  if (!export_name->Equals(ReadOnlyRoots(isolate).default_string())) {
    // Go through all star exports looking for the given name.  If multiple star
    // exports provide the name, make sure they all map it to the same cell.
    Handle<Cell> unique_cell;
    DirectHandle<FixedArray> special_exports(module->info()->special_exports(),
                                             isolate);
    for (int i = 0, n = special_exports->length(); i < n; ++i) {
      i::DirectHandle<i::SourceTextModuleInfoEntry> entry(
          i::Cast<i::SourceTextModuleInfoEntry>(special_exports->get(i)),
          isolate);
      if (!IsUndefined(entry->export_name(), isolate)) {
        continue;  // Indirect export.
      }

      Handle<Script> script(module->GetScript(), isolate);
      MessageLocation new_loc(script, entry->beg_pos(), entry->end_pos());

      Handle<Cell> cell;
      if (ResolveImport(isolate, module, export_name, entry->module_request(),
                        new_loc, false, resolve_set)
              .ToHandle(&cell)) {
        if (unique_cell.is_null()) unique_cell = cell;
        if (*unique_cell != *cell) {
          isolate->ThrowAt(isolate->factory()->NewSyntaxError(
                               MessageTemplate::kAmbiguousExport,
                               module_specifier, export_name),
                           &loc);
          return MaybeHandle<Cell>();
        }
      } else if (isolate->has_exception()) {
        return MaybeHandle<Cell>();
      }
    }

    if (!unique_cell.is_null()) {
      // Found a unique star export for this name.
      Handle<ObjectHashTable> exports(module->exports(), isolate);
      DCHECK(IsTheHole(exports->Lookup(export_name), isolate));
      exports = ObjectHashTable::Put(exports, export_name, unique_cell);
      module->set_exports(*exports);
      return unique_cell;
    }
  }

  // Unresolvable.
  if (must_resolve) {
    isolate->ThrowAt(
        isolate->factory()->NewSyntaxError(MessageTemplate::kUnresolvableExport,
                                           module_specifier, export_name),
        &loc);
    return MaybeHandle<Cell>();
  }
  return MaybeHandle<Cell>();
}

bool SourceTextModule::PrepareInstantiate(
    Isolate* isolate, Handle<SourceTextModule> module,
    v8::Local<v8::Context> context,
    v8::Module::ResolveModuleCallback module_callback,
    v8::Module::ResolveSourceCallback source_callback) {
  DCHECK_NE(module_callback, nullptr);
  // Obtain requested modules.
  DirectHandle<SourceTextModuleInfo> module_info(module->info(), isolate);
  DirectHandle<FixedArray> module_requests(module_info->module_requests(),
                                           isolate);
  DirectHandle<FixedArray> requested_modules(module->requested_modules(),
                                             isolate);
  for (int i = 0, length = module_requests->length(); i < length; ++i) {
    DirectHandle<ModuleRequest> module_request(
        Cast<ModuleRequest>(module_requests->get(i)), isolate);
    Handle<String> specifier(module_request->specifier(), isolate);
    Handle<FixedArray> import_attributes(module_request->import_attributes(),
                                         isolate);
    switch (module_request->phase()) {
      case ModuleImportPhase::kEvaluation: {
        v8::Local<v8::Module> api_requested_module;
        if (!module_callback(context, v8::Utils::ToLocal(specifier),
                             v8::Utils::FixedArrayToLocal(import_attributes),
                             v8::Utils::ToLocal(Cast<Module>(module)))
                 .ToLocal(&api_requested_module)) {
          return false;
        }
        DirectHandle<Module> requested_module =
            Utils::OpenDirectHandle(*api_requested_module);
        requested_modules->set(i, *requested_module);
        break;
      }
      case ModuleImportPhase::kSource: {
        DCHECK(v8_flags.js_source_phase_imports);
#if V8_ENABLE_WEBASSEMBLY
        v8::Local<v8::Object> api_requested_module_source;
        if (!source_callback(context, v8::Utils::ToLocal(specifier),
                             v8::Utils::FixedArrayToLocal(import_attributes),
                             v8::Utils::ToLocal(Cast<Module>(module)))
                 .ToLocal(&api_requested_module_source)) {
          return false;
        }
        DirectHandle<JSReceiver> requested_module_source =
            Utils::OpenDirectHandle(*api_requested_module_source);
        CHECK(IsWasmModuleObject(*requested_module_source));
        requested_modules->set(i, *requested_module_source);
        break;
#else
        // Only WebAssembly modules can be requested in the source phase.
        UNREACHABLE();
#endif
      }
      default:
        UNREACHABLE();
    }
  }

  // Recurse.
  for (int i = 0, length = requested_modules->length(); i < length; ++i) {
    DirectHandle<ModuleRequest> module_request(
        Cast<ModuleRequest>(module_requests->get(i)), isolate);
    if (module_request->phase() != ModuleImportPhase::kEvaluation) {
      continue;
    }
    Handle<Module> requested_module(Cast<Module>(requested_modules->get(i)),
                                    isolate);
    if (!Module::PrepareInstantiate(isolate, requested_module, context,
                                    module_callback, source_callback)) {
      return false;
    }
  }

  // Set up local exports.
  // TODO(neis): Create regular_exports array here instead of in factory method?
  for (int i = 0, n = module_info->RegularExportCount(); i < n; ++i) {
    int cell_index = module_info->RegularExportCellIndex(i);
    DirectHandle<FixedArray> export_names(
        module_info->RegularExportExportNames(i), isolate);
    CreateExport(isolate, module, cell_index, export_names);
  }

  // Partially set up indirect exports.
  // For each indirect export, we create the appropriate slot in the export
  // table and store its SourceTextModuleInfoEntry there.  When we later find
  // the correct Cell in the module that actually provides the value, we replace
  // the SourceTextModuleInfoEntry by that Cell (see ResolveExport).
  DirectHandle<FixedArray> special_exports(module_info->special_exports(),
                                           isolate);
  for (int i = 0, n = special_exports->length(); i < n; ++i) {
    Handle<SourceTextModuleInfoEntry> entry(
        Cast<SourceTextModuleInfoEntry>(special_exports->get(i)), isolate);
    Handle<Object> export_name(entry->export_name(), isolate);
    if (IsUndefined(*export_name, isolate)) continue;  // Star export.
    CreateIndirectExport(isolate, module, Cast<String>(export_name), entry);
  }

  DCHECK_EQ(module->status(), kPreLinking);
  return true;
}

bool SourceTextModule::RunInitializationCode(
    Isolate* isolate, DirectHandle<SourceTextModule> module) {
  DCHECK_EQ(module->status(), kLinking);
  Handle<JSFunction> function(Cast<JSFunction>(module->code()), isolate);
  DCHECK_EQ(MODULE_SCOPE, function->shared()->scope_info()->scope_type());
  Handle<Object> receiver = isolate->factory()->undefined_value();

  DirectHandle<ScopeInfo> scope_info(function->shared()->scope_info(), isolate);
  DirectHandle<Context> context = isolate->factory()->NewModuleContext(
      module, isolate->native_context(), scope_info);
  function->set_context(*context);

  MaybeHandle<Object> maybe_generator =
      Execution::Call(isolate, function, receiver, 0, {});
  Handle<Object> generator;
  if (!maybe_generator.ToHandle(&generator)) {
    DCHECK(isolate->has_exception());
    return false;
  }
  DCHECK_EQ(*function, Cast<JSGeneratorObject>(generator)->function());
  module->set_code(Cast<JSGeneratorObject>(*generator));
  return true;
}

// ES#sec-innermoduleevaluation and ES#sec-innermodulelinking
bool SourceTextModule::MaybeTransitionComponent(
    Isolate* isolate, DirectHandle<SourceTextModule> module,
    ZoneForwardList<Handle<SourceTextModule>>* stack, Status new_status) {
  DCHECK(new_status == kLinked || new_status == kEvaluated);

#ifdef DEBUG
  if (v8_flags.trace_module_status) {
    StdoutStream os;
    os << "Transitioning strongly connected module graph component to "
       << Module::StatusString(new_status) << " {\n";
  }
#endif  // DEBUG

  // Below, N/M means step N in InnerModuleEvaluation and step M in
  // InnerModuleLinking.

  // 14/11. Assert: module occurs exactly once in stack.
  SLOW_DCHECK(
      // {module} is on the {stack}.
      std::count_if(stack->begin(), stack->end(), [&](DirectHandle<Module> m) {
        return *m == *module;
      }) == 1);

  // 15/12. Assert: module.[[DFSAncestorIndex]] ≤ module.[[DFSIndex]].
  DCHECK_LE(module->dfs_ancestor_index(), module->dfs_index());

  // 16/13. If module.[[DFSAncestorIndex]] = module.[[DFSIndex]], then
  if (module->dfs_ancestor_index() == module->dfs_index()) {
    // This is the root of its strongly connected component.
    DirectHandle<SourceTextModule> cycle_root = module;
    DirectHandle<SourceTextModule> ancestor;
    // This loop handles the loops in both InnerModuleEvaluation and
    // InnerModuleLinking.
    //
    // InnerModuleEvaluation
    //
    // a. Let done be false.
    // b. Repeat, while done is false,
    //     i. Let requiredModule be the last element of stack.
    //    ii. Remove the last element of stack.
    //   iii. Assert: requiredModule is a Cyclic Module Record.
    //    iv. If requiredModule.[[AsyncEvaluation]] is false, set
    //        requiredModule.[[Status]] to EVALUATED.
    //     v. Otherwise, set requiredModule.[[Status]] to EVALUATING-ASYNC.
    //    vi. If requiredModule and module are the same Module Record, set done
    //        to true.
    //   vii. Set requiredModule.[[CycleRoot]] to module.
    //
    // InnerModuleLinking
    //
    // a. Let done be false.
    // b. Repeat, while done is false,
    //     i. Let requiredModule be the last element of stack.
    //    ii. Remove the last element of stack.
    //   iii. Assert: requiredModule is a Cyclic Module Record.
    //    iv. Set requiredModule.[[Status]] to LINKED.
    //     v. If requiredModule and module are the same Module Record, set done
    //        to true.
    do {
      ancestor = stack->front();
      stack->pop_front();
      DCHECK_EQ(ancestor->status(),
                new_status == kLinked ? kLinking : kEvaluating);
      if (new_status == kLinked) {
        if (!SourceTextModule::RunInitializationCode(isolate, ancestor)) {
          return false;
        }
        ancestor->SetStatus(kLinked);
      } else {
        DCHECK(IsTheHole(ancestor->cycle_root(), isolate));
        ancestor->set_cycle_root(*cycle_root);
        ancestor->SetStatus(ancestor->HasAsyncEvaluationOrdinal()
                                ? kEvaluatingAsync
                                : kEvaluated);
      }
    } while (*ancestor != *module);
  }
#ifdef DEBUG
  if (v8_flags.trace_module_status) {
    StdoutStream os;
    os << "}\n";
  }
#endif  // DEBUG
  return true;
}

bool SourceTextModule::FinishInstantiate(
    Isolate* isolate, Handle<SourceTextModule> module,
    ZoneForwardList<Handle<SourceTextModule>>* stack, unsigned* dfs_index,
    Zone* zone) {
  // Instantiate SharedFunctionInfo and mark module as instantiating for
  // the recursion.
  Handle<SharedFunctionInfo> shared(Cast<SharedFunctionInfo>(module->code()),
                                    isolate);
  DirectHandle<JSFunction> function =
      Factory::JSFunctionBuilder{isolate, shared, isolate->native_context()}
          .Build();
  module->set_code(*function);
  module->SetStatus(kLinking);
  module->set_dfs_index(*dfs_index);
  module->set_dfs_ancestor_index(*dfs_index);
  stack->push_front(module);
  (*dfs_index)++;

  // Recurse.
  DirectHandle<FixedArray> module_requests(module->info()->module_requests(),
                                           isolate);
  DirectHandle<FixedArray> requested_modules(module->requested_modules(),
                                             isolate);
  for (int i = 0, length = requested_modules->length(); i < length; ++i) {
    DirectHandle<ModuleRequest> module_request(
        Cast<ModuleRequest>(module_requests->get(i)), isolate);
    if (module_request->phase() != ModuleImportPhase::kEvaluation) {
      continue;
    }
    Handle<Module> requested_module(Cast<Module>(requested_modules->get(i)),
                                    isolate);
    if (!Module::FinishInstantiate(isolate, requested_module, stack, dfs_index,
                                   zone)) {
      return false;
    }

    DCHECK_NE(requested_module->status(), kEvaluating);
    DCHECK_GE(requested_module->status(), kLinking);
    SLOW_DCHECK(
        // {requested_module} is instantiating iff it's on the {stack}.
        (requested_module->status() == kLinking) ==
        std::count_if(
            stack->begin(), stack->end(),
            [&](DirectHandle<Module> m) { return *m == *requested_module; }));

    if (requested_module->status() == kLinking) {
      // SyntheticModules go straight to kLinked so this must be a
      // SourceTextModule
      module->set_dfs_ancestor_index(std::min(
          module->dfs_ancestor_index(),
          Cast<SourceTextModule>(*requested_module)->dfs_ancestor_index()));
    }
  }

  Handle<Script> script(module->GetScript(), isolate);
  DirectHandle<SourceTextModuleInfo> module_info(module->info(), isolate);

  // Resolve imports.
  DirectHandle<FixedArray> regular_imports(module_info->regular_imports(),
                                           isolate);
  for (int i = 0, n = regular_imports->length(); i < n; ++i) {
    DirectHandle<SourceTextModuleInfoEntry> entry(
        Cast<SourceTextModuleInfoEntry>(regular_imports->get(i)), isolate);
    Handle<String> name(Cast<String>(entry->import_name()), isolate);
    MessageLocation loc(script, entry->beg_pos(), entry->end_pos());
    ResolveSet resolve_set(zone);
    Handle<Cell> cell;
    if (!ResolveImport(isolate, module, name, entry->module_request(), loc,
                       true, &resolve_set)
             .ToHandle(&cell)) {
      return false;
    }
    module->regular_imports()->set(ImportIndex(entry->cell_index()), *cell);
  }

  // Resolve indirect exports.
  DirectHandle<FixedArray> special_exports(module_info->special_exports(),
                                           isolate);
  for (int i = 0, n = special_exports->length(); i < n; ++i) {
    DirectHandle<SourceTextModuleInfoEntry> entry(
        Cast<SourceTextModuleInfoEntry>(special_exports->get(i)), isolate);
    Handle<Object> name(entry->export_name(), isolate);
    if (IsUndefined(*name, isolate)) continue;  // Star export.
    MessageLocation loc(script, entry->beg_pos(), entry->end_pos());
    ResolveSet resolve_set(zone);
    if (ResolveExport(isolate, module, Handle<String>(), Cast<String>(name),
                      loc, true, &resolve_set)
            .is_null()) {
      return false;
    }
  }

  return MaybeTransitionComponent(isolate, module, stack, kLinked);
}

void SourceTextModule::FetchStarExports(Isolate* isolate,
                                        Handle<SourceTextModule> module,
                                        Zone* zone,
                                        UnorderedModuleSet* visited) {
  DCHECK_GE(module->status(), Module::kLinking);

  if (IsJSModuleNamespace(module->module_namespace())) return;  // Shortcut.

  bool cycle = !visited->insert(module).second;
  if (cycle) return;
  Handle<ObjectHashTable> exports(module->exports(), isolate);
  UnorderedStringMap more_exports(zone);

  // TODO(neis): Only allocate more_exports if there are star exports.
  // Maybe split special_exports into indirect_exports and star_exports.

  ReadOnlyRoots roots(isolate);
  DirectHandle<FixedArray> special_exports(module->info()->special_exports(),
                                           isolate);
  for (int i = 0, n = special_exports->length(); i < n; ++i) {
    DirectHandle<SourceTextModuleInfoEntry> entry(
        Cast<SourceTextModuleInfoEntry>(special_exports->get(i)), isolate);
    if (!IsUndefined(entry->export_name(), roots)) {
      continue;  // Indirect export.
    }

    DCHECK_EQ(Cast<ModuleRequest>(module->info()->module_requests()->get(
                                      entry->module_request()))
                  ->phase(),
              ModuleImportPhase::kEvaluation);
    Handle<Module> requested_module(
        Cast<Module>(module->requested_modules()->get(entry->module_request())),
        isolate);

    // Recurse.
    if (IsSourceTextModule(*requested_module))
      FetchStarExports(isolate, Cast<SourceTextModule>(requested_module), zone,
                       visited);

    // Collect all of [requested_module]'s exports that must be added to
    // [module]'s exports (i.e. to [exports]).  We record these in
    // [more_exports].  Ambiguities (conflicting exports) are marked by mapping
    // the name to undefined instead of a Cell.
    DirectHandle<ObjectHashTable> requested_exports(requested_module->exports(),
                                                    isolate);
    for (InternalIndex index : requested_exports->IterateEntries()) {
      Tagged<Object> key;
      if (!requested_exports->ToKey(roots, index, &key)) continue;
      Handle<String> name(Cast<String>(key), isolate);

      if (name->Equals(roots.default_string())) continue;
      if (!IsTheHole(exports->Lookup(name), roots)) continue;

      Handle<Cell> cell(Cast<Cell>(requested_exports->ValueAt(index)), isolate);
      auto insert_result = more_exports.insert(std::make_pair(name, cell));
      if (!insert_result.second) {
        auto it = insert_result.first;
        if (*it->second == *cell || IsUndefined(*it->second, roots)) {
          // We already recorded this mapping before, or the name is already
          // known to be ambiguous.  In either case, there's nothing to do.
        } else {
          DCHECK(IsCell(*it->second));
          // Different star exports provide different cells for this name, hence
          // mark the name as ambiguous.
          it->second = roots.undefined_value_handle();
        }
      }
    }
  }

  // Copy [more_exports] into [exports].
  for (const auto& elem : more_exports) {
    if (IsUndefined(*elem.second, isolate)) continue;  // Ambiguous export.
    DCHECK(!elem.first->Equals(ReadOnlyRoots(isolate).default_string()));
    DCHECK(IsCell(*elem.second));
    exports = ObjectHashTable::Put(exports, elem.first, elem.second);
  }
  module->set_exports(*exports);
}

void SourceTextModule::GatherAvailableAncestors(
    Isolate* isolate, Zone* zone, Handle<SourceTextModule> start,
    AvailableAncestorsSet* exec_list) {
  // The spec algorithm is recursive. It is transformed to an equivalent
  // iterative one here.
  ZoneStack<Handle<SourceTextModule>> worklist(zone);
  worklist.push(start);

  while (!worklist.empty()) {
    DirectHandle<SourceTextModule> module = worklist.top();
    worklist.pop();

    // 1. For each Module m of module.[[AsyncParentModules]], do
    for (int i = module->AsyncParentModuleCount(); i-- > 0;) {
      Handle<SourceTextModule> m = module->GetAsyncParentModule(isolate, i);

      // a. If execList does not contain m and
      //    m.[[CycleRoot]].[[EvaluationError]] is empty, then
      if (m->GetCycleRoot(isolate)->status() != kErrored &&
          exec_list->find(m) == exec_list->end()) {
        // i. Assert: m.[[Status]] is EVALUATING-ASYNC.
        // ii. Assert: m.[[EvaluationError]] is empty.
        DCHECK_EQ(m->status(), kEvaluatingAsync);

        // iii. Assert: m.[[AsyncEvaluation]] is true.
        DCHECK(m->HasAsyncEvaluationOrdinal());

        // iv. Assert: m.[[PendingAsyncDependencies]] > 0.
        DCHECK(m->HasPendingAsyncDependencies());

        // v. Set m.[[PendingAsyncDependencies]] to
        //    m.[[PendingAsyncDependencies]] - 1.
        m->DecrementPendingAsyncDependencies();

        // vi. If m.[[PendingAsyncDependencies]] = 0, then
        if (!m->HasPendingAsyncDependencies()) {
          // 1. Append m to execList.
          exec_list->insert(m);

          // 2. If m.[[HasTLA]] is false,
          //    perform ! GatherAvailableAncestors(m, execList).
          if (!m->has_toplevel_await()) worklist.push(m);
        }
      }
    }
  }

  // 2. Return UNUSED.
}

Handle<JSModuleNamespace> SourceTextModule::GetModuleNamespace(
    Isolate* isolate, DirectHandle<SourceTextModule> module,
    int module_request) {
  DCHECK_EQ(Cast<ModuleRequest>(
                module->info()->module_requests()->get(module_request))
                ->phase(),
            ModuleImportPhase::kEvaluation);
  Handle<Module> requested_module(
      Cast<Module>(module->requested_modules()->get(module_request)), isolate);
  return Module::GetModuleNamespace(isolate, requested_module);
}

MaybeHandle<JSObject> SourceTextModule::GetImportMeta(
    Isolate* isolate, Handle<SourceTextModule> module) {
  Handle<UnionOf<JSObject, Hole>> import_meta(module->import_meta(kAcquireLoad),
                                              isolate);
  if (IsTheHole(*import_meta, isolate)) {
    if (!isolate->RunHostInitializeImportMetaObjectCallback(module).ToHandle(
            &import_meta)) {
      return {};
    }
    module->set_import_meta(*import_meta, kReleaseStore);
  }
  return Cast<JSObject>(import_meta);
}

// ES#sec-moduleevaluation
bool SourceTextModule::MaybeHandleEvaluationException(
    Isolate* isolate, ZoneForwardList<Handle<SourceTextModule>>* stack) {
  DisallowGarbageCollection no_gc;
  Tagged<Object> exception = isolate->exception();
  // Step 9.
  if (isolate->is_catchable_by_javascript(exce
```