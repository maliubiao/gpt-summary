Response: The user wants a summary of the functionality of the C++ source code file `v8/src/init/bootstrapper.cc`. This is the first of six parts.

Based on the included headers and the namespace `v8::internal`, this file seems to be a core component of the V8 JavaScript engine, responsible for setting up the initial environment needed to execute JavaScript code.

Here's a breakdown of the key functionalities observed from the included headers:

* **`#include "src/init/bootstrapper.h"`**:  This suggests the file defines the `Bootstrapper` class.
* **`#include "include/v8-function.h"`**, **`#include "src/objects/js-array.h"`**, etc.: Inclusion of various V8 object headers indicates that this file deals with the creation and initialization of core JavaScript objects and functions.
* **`#include "src/execution/isolate-inl.h"`**: This implies interaction with the `Isolate`, which represents an isolated instance of the V8 engine.
* **`#include "src/heap/heap-inl.h"`**: This suggests memory management and heap initialization are part of the process.
* **`#include "src/snapshot/snapshot.h"`**: This hints at the ability to load from or create snapshots of the initial state.
* **Extension-related headers**: Includes for `GCExtension`, `StatisticsExtension`, etc., suggest handling of built-in extensions.

Therefore, the primary function of this part of `bootstrapper.cc` seems to be setting up the very basic infrastructure and initial objects of the V8 JavaScript environment.

Regarding the relationship with JavaScript, this file is *fundamental*. It's responsible for creating the core JavaScript objects and functions that are available in every JavaScript environment (like `Object`, `Function`, `Array`, etc.). Without the `Bootstrapper`, no JavaScript code could run.

Let's consider a simple JavaScript example and how this C++ code relates:

```javascript
const arr = [1, 2, 3];
console.log(arr.length);
```

The `Bootstrapper` is responsible for:

1. **Creating the `Array` constructor function**: This is a JavaScript function object accessible via the global `Array`. The C++ code in this file would contain the logic to create this function and link it to its underlying C++ implementation.
2. **Creating the `Array.prototype` object**: This object holds the common methods for arrays, such as `push`, `pop`, and importantly, `length`.
3. **Making `arr` an instance of `Array`**: When `[1, 2, 3]` is evaluated, V8 uses the `Array` constructor (created by the `Bootstrapper`) to create the `arr` object and set its internal prototype to `Array.prototype`.
4. **Providing the `length` property**: The `length` property, accessed in `arr.length`, is a property defined on `Array.prototype`. The `Bootstrapper` sets up this relationship.
5. **Creating the `console` object and `log` method**: Similarly, the `console` object and its `log` method are also set up during the bootstrapping process.

Essentially, this C++ code defines the initial blueprint and creates the foundational elements upon which all JavaScript code execution is built.
This section of the `bootstrapper.cc` file focuses on the **initialization of the V8 JavaScript engine's core environment**. Its primary function is to set up the essential building blocks that allow JavaScript code to run.

Here's a breakdown of its key responsibilities as seen in this part:

* **Defines the `Bootstrapper` class**: This class is the central component responsible for the bootstrapping process.
* **Manages a cache for extensions**: The `extensions_cache_` member suggests that this part handles the loading and management of built-in extensions to the JavaScript environment.
* **Registers core extensions**: The `InitializeOncePerProcess` method registers fundamental extensions like `GCExtension` (for garbage collection), `StatisticsExtension`, etc., making these functionalities available in the JavaScript environment.
* **Defines the `Genesis` class**: This nested class seems to handle the creation of the initial context and core JavaScript objects.
* **Creates the initial `NativeContext`**: The `NativeContext` holds the global state for a JavaScript execution environment.
* **Creates fundamental JavaScript objects**:  The `Genesis` class is responsible for creating core objects like the `empty_function`, and setting up maps for different function types (strict, sloppy, with/without prototype).
* **Creates the `Object` constructor and its prototype**: This is a crucial step in setting up the prototype chain.
* **Creates maps for various object types**:  Maps (in V8's internal representation) are created for different kinds of objects (e.g., functions, iterators, proxies) to optimize property access.
* **Sets up restricted function properties**: The code handles setting up the `arguments` and `caller` properties on strict-mode functions to throw errors when accessed.
* **Manages the list of active native contexts**: The `AddToWeakNativeContextList` function suggests a mechanism for tracking active JavaScript environments.
* **Creates the global object and global proxy**: This involves setting up the initial global scope where JavaScript code starts executing.
* **Handles Object Templates**: The code interacts with `v8::ObjectTemplate` to allow customization of the global object by the embedder.

**Relationship with JavaScript and Examples:**

This C++ code is the **foundation** upon which all JavaScript functionality is built. It creates the very objects and functions that JavaScript code relies on.

For example, consider these simple JavaScript snippets:

```javascript
// Example 1: Using the Object constructor
const obj = new Object();
obj.property = 10;

// Example 2: Using an array
const arr = [1, 2, 3];
console.log(arr.length);

// Example 3: Defining a function
function myFunction() {
  "use strict";
  // Accessing arguments would throw an error due to bootstrapping
  // console.log(arguments);
}
```

Here's how the C++ code in this file relates to these examples:

* **`new Object()`**: The `Genesis::CreateObjectFunction` method creates the JavaScript `Object` constructor function. When `new Object()` is called, this constructor (created in C++) is invoked to create the `obj` instance. The initial map and prototype for regular objects are also set up here.
* **`const arr = [1, 2, 3];`**:  While not explicitly shown in this part, the bootstrapping process also sets up the `Array` constructor (likely in a subsequent part). The C++ code would define the `Array` constructor and its associated prototype, allowing the creation of array objects like `arr`.
* **`console.log()`**: The `Bootstrapper::InitializeConsole` method (likely in a later part, but the setup starts here) registers the `console` object and its methods like `log`. The extensions mechanism is used to make these browser-specific APIs available.
* **`function myFunction() { "use strict"; ... }`**: The `Genesis::CreateSloppyModeFunctionMaps` and `Genesis::CreateStrictModeFunctionMaps` methods create the internal maps used for functions. The handling of `"use strict"` and the restricted `arguments` and `caller` properties are configured during the bootstrapping process. The `AddRestrictedFunctionProperties` method within `Genesis` directly contributes to this behavior.

In essence, this part of the `bootstrapper.cc` file is responsible for the **"Big Bang"** of the JavaScript environment. It creates the initial primordial objects and functions that make JavaScript execution possible. Without this foundational setup, no JavaScript code could run.

Prompt: 
```
这是目录为v8/src/init/bootstrapper.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共6部分，请归纳一下它的功能

"""
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/init/bootstrapper.h"

#include "include/v8-function.h"
#include "src/api/api-inl.h"
#include "src/api/api-natives.h"
#include "src/base/hashmap.h"
#include "src/base/ieee754.h"
#include "src/builtins/accessors.h"
#include "src/codegen/compiler.h"
#include "src/common/globals.h"
#include "src/debug/debug.h"
#include "src/execution/isolate-inl.h"
#include "src/execution/microtask-queue.h"
#include "src/execution/protectors.h"
#include "src/extensions/cputracemark-extension.h"
#include "src/extensions/externalize-string-extension.h"
#include "src/extensions/gc-extension.h"
#include "src/extensions/ignition-statistics-extension.h"
#include "src/extensions/statistics-extension.h"
#include "src/extensions/trigger-failure-extension.h"
#include "src/logging/runtime-call-stats-scope.h"
#include "src/objects/instance-type.h"
#include "src/objects/js-array.h"
#include "src/objects/objects.h"
#include "src/sandbox/testing.h"
#ifdef ENABLE_VTUNE_TRACEMARK
#include "src/extensions/vtunedomain-support-extension.h"
#endif  // ENABLE_VTUNE_TRACEMARK
#include "src/heap/heap-inl.h"
#include "src/logging/counters.h"
#include "src/logging/log.h"
#include "src/numbers/math-random.h"
#include "src/objects/api-callbacks.h"
#include "src/objects/arguments.h"
#include "src/objects/function-kind.h"
#include "src/objects/hash-table-inl.h"
#ifdef V8_INTL_SUPPORT
#include "src/objects/intl-objects.h"
#endif  // V8_INTL_SUPPORT
#include "src/objects/js-array-buffer-inl.h"
#include "src/objects/js-array-inl.h"
#include "src/objects/js-atomics-synchronization.h"
#include "src/objects/js-disposable-stack.h"
#include "src/objects/js-iterator-helpers.h"
#ifdef V8_INTL_SUPPORT
#include "src/objects/js-break-iterator.h"
#include "src/objects/js-collator.h"
#include "src/objects/js-date-time-format.h"
#include "src/objects/js-display-names.h"
#include "src/objects/js-duration-format.h"
#include "src/objects/js-list-format.h"
#include "src/objects/js-locale.h"
#include "src/objects/js-number-format.h"
#include "src/objects/js-plural-rules.h"
#endif  // V8_INTL_SUPPORT
#include "src/objects/js-regexp-string-iterator.h"
#include "src/objects/js-regexp.h"
#include "src/objects/js-shadow-realm.h"
#ifdef V8_INTL_SUPPORT
#include "src/objects/js-relative-time-format.h"
#include "src/objects/js-segment-iterator.h"
#include "src/objects/js-segmenter.h"
#include "src/objects/js-segments.h"
#endif  // V8_INTL_SUPPORT
#include "src/codegen/script-details.h"
#include "src/objects/js-raw-json.h"
#include "src/objects/js-shared-array.h"
#include "src/objects/js-struct.h"
#include "src/objects/js-temporal-objects-inl.h"
#include "src/objects/js-weak-refs.h"
#include "src/objects/ordered-hash-table.h"
#include "src/objects/property-cell.h"
#include "src/objects/property-descriptor.h"
#include "src/objects/slots-inl.h"
#include "src/objects/swiss-name-dictionary-inl.h"
#include "src/objects/templates.h"
#include "src/snapshot/snapshot.h"
#include "src/zone/zone-hashmap.h"

#ifdef V8_FUZZILLI
#include "src/fuzzilli/fuzzilli.h"
#endif

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/wasm-js.h"
#endif  // V8_ENABLE_WEBASSEMBLY

namespace v8 {
namespace internal {

void SourceCodeCache::Initialize(Isolate* isolate, bool create_heap_objects) {
  cache_ = create_heap_objects ? ReadOnlyRoots(isolate).empty_fixed_array()
                               : Tagged<FixedArray>();
}

void SourceCodeCache::Iterate(RootVisitor* v) {
  v->VisitRootPointer(Root::kExtensions, nullptr, FullObjectSlot(&cache_));
}

bool SourceCodeCache::Lookup(Isolate* isolate, base::Vector<const char> name,
                             DirectHandle<SharedFunctionInfo>* handle) {
  for (int i = 0; i < cache_->length(); i += 2) {
    Tagged<SeqOneByteString> str = Cast<SeqOneByteString>(cache_->get(i));
    if (str->IsOneByteEqualTo(name)) {
      *handle =
          direct_handle(Cast<SharedFunctionInfo>(cache_->get(i + 1)), isolate);
      return true;
    }
  }
  return false;
}

void SourceCodeCache::Add(Isolate* isolate, base::Vector<const char> name,
                          DirectHandle<SharedFunctionInfo> shared) {
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);
  int length = cache_->length();
  DirectHandle<FixedArray> new_array =
      factory->NewFixedArray(length + 2, AllocationType::kOld);
  FixedArray::CopyElements(isolate, *new_array, 0, cache_, 0, cache_->length());
  cache_ = *new_array;
  Handle<String> str =
      factory
          ->NewStringFromOneByte(base::Vector<const uint8_t>::cast(name),
                                 AllocationType::kOld)
          .ToHandleChecked();
  DCHECK(!str.is_null());
  cache_->set(length, *str);
  cache_->set(length + 1, *shared);
  Cast<Script>(shared->script())->set_type(type_);
}

Bootstrapper::Bootstrapper(Isolate* isolate)
    : isolate_(isolate),
      nesting_(0),
      extensions_cache_(Script::Type::kExtension) {}

void Bootstrapper::Initialize(bool create_heap_objects) {
  extensions_cache_.Initialize(isolate_, create_heap_objects);
}

static const char* GCFunctionName() {
  bool flag_given =
      v8_flags.expose_gc_as != nullptr && strlen(v8_flags.expose_gc_as) != 0;
  return flag_given ? v8_flags.expose_gc_as : "gc";
}

static bool isValidCpuTraceMarkFunctionName() {
  return v8_flags.expose_cputracemark_as != nullptr &&
         strlen(v8_flags.expose_cputracemark_as) != 0;
}

void Bootstrapper::InitializeOncePerProcess() {
  v8::RegisterExtension(std::make_unique<GCExtension>(GCFunctionName()));
#ifdef V8_FUZZILLI
  v8::RegisterExtension(std::make_unique<FuzzilliExtension>("fuzzilli"));
#endif
  v8::RegisterExtension(std::make_unique<ExternalizeStringExtension>());
  v8::RegisterExtension(std::make_unique<StatisticsExtension>());
  v8::RegisterExtension(std::make_unique<TriggerFailureExtension>());
  v8::RegisterExtension(std::make_unique<IgnitionStatisticsExtension>());
  if (isValidCpuTraceMarkFunctionName()) {
    v8::RegisterExtension(std::make_unique<CpuTraceMarkExtension>(
        v8_flags.expose_cputracemark_as));
  }
#ifdef ENABLE_VTUNE_TRACEMARK
  v8::RegisterExtension(
      std::make_unique<VTuneDomainSupportExtension>("vtunedomainmark"));
#endif  // ENABLE_VTUNE_TRACEMARK
}

void Bootstrapper::TearDown() {
  extensions_cache_.Initialize(isolate_, false);  // Yes, symmetrical
}

class Genesis {
 public:
  Genesis(Isolate* isolate, MaybeHandle<JSGlobalProxy> maybe_global_proxy,
          v8::Local<v8::ObjectTemplate> global_proxy_template,
          size_t context_snapshot_index,
          DeserializeEmbedderFieldsCallback embedder_fields_deserializer,
          v8::MicrotaskQueue* microtask_queue);
  Genesis(Isolate* isolate, MaybeHandle<JSGlobalProxy> maybe_global_proxy,
          v8::Local<v8::ObjectTemplate> global_proxy_template);
  ~Genesis() = default;

  Isolate* isolate() const { return isolate_; }
  Factory* factory() const { return isolate_->factory(); }
  Builtins* builtins() const { return isolate_->builtins(); }
  Heap* heap() const { return isolate_->heap(); }

  DirectHandle<NativeContext> result() { return result_; }

  DirectHandle<JSGlobalProxy> global_proxy() { return global_proxy_; }

 private:
  DirectHandle<NativeContext> native_context() { return native_context_; }

  // Creates some basic objects. Used for creating a context from scratch.
  void CreateRoots();
  // Creates the empty function.  Used for creating a context from scratch.
  Handle<JSFunction> CreateEmptyFunction();
  // Returns the %ThrowTypeError% intrinsic function.
  // See ES#sec-%throwtypeerror% for details.
  DirectHandle<JSFunction> GetThrowTypeErrorIntrinsic();

  void CreateSloppyModeFunctionMaps(Handle<JSFunction> empty);
  void CreateStrictModeFunctionMaps(Handle<JSFunction> empty);
  void CreateObjectFunction(DirectHandle<JSFunction> empty);
  void CreateIteratorMaps(Handle<JSFunction> empty);
  void CreateAsyncIteratorMaps(Handle<JSFunction> empty);
  void CreateAsyncFunctionMaps(Handle<JSFunction> empty);
  void CreateJSProxyMaps();

  // Make the "arguments" and "caller" properties throw a TypeError on access.
  void AddRestrictedFunctionProperties(DirectHandle<JSFunction> empty);

  // Creates the global objects using the global proxy and the template passed
  // in through the API.  We call this regardless of whether we are building a
  // context from scratch or using a deserialized one from the context snapshot
  // but in the latter case we don't use the objects it produces directly, as
  // we have to use the deserialized ones that are linked together with the
  // rest of the context snapshot. At the end we link the global proxy and the
  // context to each other.
  Handle<JSGlobalObject> CreateNewGlobals(
      v8::Local<v8::ObjectTemplate> global_proxy_template,
      DirectHandle<JSGlobalProxy> global_proxy);
  // Similarly, we want to use the global that has been created by the templates
  // passed through the API.  The global from the snapshot is detached from the
  // other objects in the snapshot.
  void HookUpGlobalObject(Handle<JSGlobalObject> global_object);
  // Hooks the given global proxy into the context in the case we do not
  // replace the global object from the deserialized native context.
  void HookUpGlobalProxy(DirectHandle<JSGlobalProxy> global_proxy);
  // The native context has a ScriptContextTable that store declarative bindings
  // made in script scopes.  Add a "this" binding to that table pointing to the
  // global proxy.
  void InstallGlobalThisBinding();
  // New context initialization.  Used for creating a context from scratch.
  void InitializeGlobal(Handle<JSGlobalObject> global_object,
                        Handle<JSFunction> empty_function);
  void InitializeExperimentalGlobal();
  void InitializeIteratorFunctions();
  void InitializeCallSiteBuiltins();
  void InitializeConsole(Handle<JSObject> extras_binding);

#define DECLARE_FEATURE_INITIALIZATION(id, descr) void InitializeGlobal_##id();

  HARMONY_INPROGRESS(DECLARE_FEATURE_INITIALIZATION)
  JAVASCRIPT_INPROGRESS_FEATURES(DECLARE_FEATURE_INITIALIZATION)
  HARMONY_STAGED(DECLARE_FEATURE_INITIALIZATION)
  JAVASCRIPT_STAGED_FEATURES(DECLARE_FEATURE_INITIALIZATION)
  HARMONY_SHIPPING(DECLARE_FEATURE_INITIALIZATION)
  JAVASCRIPT_SHIPPING_FEATURES(DECLARE_FEATURE_INITIALIZATION)
#undef DECLARE_FEATURE_INITIALIZATION
  void InitializeGlobal_regexp_linear_flag();
  void InitializeGlobal_sharedarraybuffer();
#if V8_ENABLE_WEBASSEMBLY
  void InitializeWasmJSPI();
#endif

  enum ArrayBufferKind { ARRAY_BUFFER, SHARED_ARRAY_BUFFER };
  Handle<JSFunction> CreateArrayBuffer(Handle<String> name,
                                       ArrayBufferKind array_buffer_kind);

  bool InstallABunchOfRandomThings();
  bool InstallExtrasBindings();

  Handle<JSFunction> InstallTypedArray(const char* name,
                                       ElementsKind elements_kind,
                                       InstanceType constructor_type,
                                       int rab_gsab_initial_map_index);
  void InitializeMapCaches();

  enum ExtensionTraversalState { UNVISITED, VISITED, INSTALLED };

  class ExtensionStates {
   public:
    ExtensionStates();
    ExtensionStates(const ExtensionStates&) = delete;
    ExtensionStates& operator=(const ExtensionStates&) = delete;
    ExtensionTraversalState get_state(RegisteredExtension* extension);
    void set_state(RegisteredExtension* extension,
                   ExtensionTraversalState state);

   private:
    base::HashMap map_;
  };

  // Used both for deserialized and from-scratch contexts to add the extensions
  // provided.
  static bool InstallExtensions(Isolate* isolate,
                                DirectHandle<Context> native_context,
                                v8::ExtensionConfiguration* extensions);
  static bool InstallAutoExtensions(Isolate* isolate,
                                    ExtensionStates* extension_states);
  static bool InstallRequestedExtensions(Isolate* isolate,
                                         v8::ExtensionConfiguration* extensions,
                                         ExtensionStates* extension_states);
  static bool InstallExtension(Isolate* isolate, const char* name,
                               ExtensionStates* extension_states);
  static bool InstallExtension(Isolate* isolate,
                               v8::RegisteredExtension* current,
                               ExtensionStates* extension_states);
  static bool InstallSpecialObjects(Isolate* isolate,
                                    DirectHandle<NativeContext> native_context);
  bool ConfigureApiObject(Handle<JSObject> object,
                          Handle<ObjectTemplateInfo> object_template);
  bool ConfigureGlobalObject(
      v8::Local<v8::ObjectTemplate> global_proxy_template);

  // Migrates all properties from the 'from' object to the 'to'
  // object and overrides the prototype in 'to' with the one from
  // 'from'.
  void TransferObject(DirectHandle<JSObject> from, Handle<JSObject> to);
  void TransferNamedProperties(DirectHandle<JSObject> from,
                               Handle<JSObject> to);
  void TransferIndexedProperties(DirectHandle<JSObject> from,
                                 DirectHandle<JSObject> to);

  Handle<Map> CreateInitialMapForArraySubclass(int size,
                                               int inobject_properties);

  static bool CompileExtension(Isolate* isolate, v8::Extension* extension);

  Isolate* isolate_;
  DirectHandle<NativeContext> result_;
  DirectHandle<NativeContext> native_context_;
  DirectHandle<JSGlobalProxy> global_proxy_;

  // %ThrowTypeError%. See ES#sec-%throwtypeerror% for details.
  DirectHandle<JSFunction> restricted_properties_thrower_;

  BootstrapperActive active_;
  friend class Bootstrapper;
};

void Bootstrapper::Iterate(RootVisitor* v) {
  extensions_cache_.Iterate(v);
  v->Synchronize(VisitorSynchronization::kExtensions);
}

DirectHandle<NativeContext> Bootstrapper::CreateEnvironment(
    MaybeHandle<JSGlobalProxy> maybe_global_proxy,
    v8::Local<v8::ObjectTemplate> global_proxy_template,
    v8::ExtensionConfiguration* extensions, size_t context_snapshot_index,
    DeserializeEmbedderFieldsCallback embedder_fields_deserializer,
    v8::MicrotaskQueue* microtask_queue) {
  HandleScope scope(isolate_);
  DirectHandle<NativeContext> env;
  {
    Genesis genesis(isolate_, maybe_global_proxy, global_proxy_template,
                    context_snapshot_index, embedder_fields_deserializer,
                    microtask_queue);
    env = genesis.result();
    if (env.is_null() || !InstallExtensions(env, extensions)) {
      return {};
    }
  }
  LogAllMaps();
  isolate_->heap()->NotifyBootstrapComplete();
  return scope.CloseAndEscape(env);
}

DirectHandle<JSGlobalProxy> Bootstrapper::NewRemoteContext(
    MaybeHandle<JSGlobalProxy> maybe_global_proxy,
    v8::Local<v8::ObjectTemplate> global_proxy_template) {
  HandleScope scope(isolate_);
  DirectHandle<JSGlobalProxy> global_proxy;
  {
    Genesis genesis(isolate_, maybe_global_proxy, global_proxy_template);
    global_proxy = genesis.global_proxy();
    if (global_proxy.is_null()) return Handle<JSGlobalProxy>();
  }
  LogAllMaps();
  return scope.CloseAndEscape(global_proxy);
}

void Bootstrapper::LogAllMaps() {
  if (!v8_flags.log_maps || isolate_->initialized_from_snapshot()) return;
  // Log all created Map objects that are on the heap. For snapshots the Map
  // logging happens during deserialization in order to avoid printing Maps
  // multiple times during partial deserialization.
  LOG(isolate_, LogAllMaps());
}

namespace {

#ifdef DEBUG
bool IsFunctionMapOrSpecialBuiltin(DirectHandle<Map> map, Builtin builtin,
                                   DirectHandle<Context> context) {
  // During bootstrapping some of these maps could be not created yet.
  return ((*map == context->get(Context::STRICT_FUNCTION_MAP_INDEX)) ||
          (*map == context->get(
                       Context::STRICT_FUNCTION_WITHOUT_PROTOTYPE_MAP_INDEX)) ||
          (*map ==
           context->get(
               Context::STRICT_FUNCTION_WITH_READONLY_PROTOTYPE_MAP_INDEX)) ||
          // Check if it's a creation of an empty or Proxy function during
          // bootstrapping.
          (builtin == Builtin::kEmptyFunction ||
           builtin == Builtin::kProxyConstructor));
}
#endif  // DEBUG

Handle<SharedFunctionInfo> CreateSharedFunctionInfoForBuiltin(
    Isolate* isolate, Handle<String> name, Builtin builtin, int len,
    AdaptArguments adapt) {
  Handle<SharedFunctionInfo> info =
      isolate->factory()->NewSharedFunctionInfoForBuiltin(name, builtin, len,
                                                          adapt);
  info->set_language_mode(LanguageMode::kStrict);

#ifdef DEBUG
  Tagged<Code> code = info->GetCode(isolate);
  if (code->parameter_count() != kDontAdaptArgumentsSentinel) {
    DCHECK_EQ(info->internal_formal_parameter_count_with_receiver(),
              code->parameter_count());
  }
#endif

  return info;
}

V8_NOINLINE Handle<JSFunction> CreateFunctionForBuiltin(
    Isolate* isolate, Handle<String> name, Handle<Map> map, Builtin builtin,
    int len, AdaptArguments adapt) {
  Handle<NativeContext> context(isolate->native_context());
  DCHECK(IsFunctionMapOrSpecialBuiltin(map, builtin, context));

  Handle<SharedFunctionInfo> info =
      CreateSharedFunctionInfoForBuiltin(isolate, name, builtin, len, adapt);

  return Factory::JSFunctionBuilder{isolate, info, context}
      .set_map(map)
      .Build();
}

V8_NOINLINE Handle<JSFunction> CreateFunctionForBuiltinWithPrototype(
    Isolate* isolate, Handle<String> name, Builtin builtin,
    Handle<UnionOf<JSPrototype, Hole>> prototype, InstanceType type,
    int instance_size, int inobject_properties,
    MutableMode prototype_mutability, int len, AdaptArguments adapt) {
  Factory* factory = isolate->factory();
  Handle<NativeContext> context(isolate->native_context());
  Handle<Map> map =
      prototype_mutability == MUTABLE
          ? isolate->strict_function_map()
          : isolate->strict_function_with_readonly_prototype_map();
  DCHECK(IsFunctionMapOrSpecialBuiltin(map, builtin, context));

  Handle<SharedFunctionInfo> info =
      CreateSharedFunctionInfoForBuiltin(isolate, name, builtin, len, adapt);
  info->set_expected_nof_properties(inobject_properties);

  Handle<JSFunction> result =
      Factory::JSFunctionBuilder{isolate, info, context}.set_map(map).Build();

  ElementsKind elements_kind;
  switch (type) {
    case JS_ARRAY_TYPE:
      elements_kind = PACKED_SMI_ELEMENTS;
      break;
    case JS_ARGUMENTS_OBJECT_TYPE:
      elements_kind = PACKED_ELEMENTS;
      break;
    default:
      elements_kind = TERMINAL_FAST_ELEMENTS_KIND;
      break;
  }
  Handle<Map> initial_map = factory->NewContextfulMapForCurrentContext(
      type, instance_size, elements_kind, inobject_properties);
  initial_map->SetConstructor(*result);
  if (type == JS_FUNCTION_TYPE) {
    DCHECK_EQ(instance_size, JSFunction::kSizeWithPrototype);
    // Since we are creating an initial map for JSFunction objects with
    // prototype slot, set the respective bit.
    initial_map->set_has_prototype_slot(true);
  }
  // TODO(littledan): Why do we have this is_generator test when
  // NewFunctionPrototype already handles finding an appropriately
  // shared prototype?
  if (!IsResumableFunction(info->kind()) && IsTheHole(*prototype, isolate)) {
    prototype = factory->NewFunctionPrototype(result);
  }
  JSFunction::SetInitialMap(isolate, result, initial_map,
                            Cast<JSPrototype>(prototype));

  return result;
}

V8_NOINLINE Handle<JSFunction> CreateFunctionForBuiltinWithoutPrototype(
    Isolate* isolate, Handle<String> name, Builtin builtin, int len,
    AdaptArguments adapt) {
  Handle<NativeContext> context(isolate->native_context());
  Handle<Map> map = isolate->strict_function_without_prototype_map();
  DCHECK(IsFunctionMapOrSpecialBuiltin(map, builtin, context));

  Handle<SharedFunctionInfo> info =
      CreateSharedFunctionInfoForBuiltin(isolate, name, builtin, len, adapt);

  return Factory::JSFunctionBuilder{isolate, info, context}
      .set_map(map)
      .Build();
}

V8_NOINLINE Handle<JSFunction> CreateFunction(
    Isolate* isolate, Handle<String> name, InstanceType type, int instance_size,
    int inobject_properties, Handle<UnionOf<JSPrototype, Hole>> prototype,
    Builtin builtin, int len, AdaptArguments adapt) {
  DCHECK(Builtins::HasJSLinkage(builtin));

  Handle<JSFunction> result = CreateFunctionForBuiltinWithPrototype(
      isolate, name, builtin, prototype, type, instance_size,
      inobject_properties, IMMUTABLE, len, adapt);

  // Make the JSFunction's prototype object fast.
  JSObject::MakePrototypesFast(handle(result->prototype(), isolate),
                               kStartAtReceiver, isolate);

  // Make the resulting JSFunction object fast.
  JSObject::MakePrototypesFast(result, kStartAtReceiver, isolate);
  result->shared()->set_native(true);
  return result;
}

V8_NOINLINE Handle<JSFunction> CreateFunction(
    Isolate* isolate, const char* name, InstanceType type, int instance_size,
    int inobject_properties, Handle<UnionOf<JSPrototype, Hole>> prototype,
    Builtin builtin, int len, AdaptArguments adapt) {
  return CreateFunction(
      isolate, isolate->factory()->InternalizeUtf8String(name), type,
      instance_size, inobject_properties, prototype, builtin, len, adapt);
}

V8_NOINLINE Handle<JSFunction> InstallFunction(
    Isolate* isolate, Handle<JSObject> target, Handle<String> name,
    InstanceType type, int instance_size, int inobject_properties,
    Handle<UnionOf<JSPrototype, Hole>> prototype, Builtin call, int len,
    AdaptArguments adapt) {
  DCHECK(Builtins::HasJSLinkage(call));
  Handle<JSFunction> function =
      CreateFunction(isolate, name, type, instance_size, inobject_properties,
                     prototype, call, len, adapt);
  JSObject::AddProperty(isolate, target, name, function, DONT_ENUM);
  return function;
}

V8_NOINLINE Handle<JSFunction> InstallFunction(
    Isolate* isolate, Handle<JSObject> target, const char* name,
    InstanceType type, int instance_size, int inobject_properties,
    Handle<UnionOf<JSPrototype, Hole>> prototype, Builtin call, int len,
    AdaptArguments adapt) {
  return InstallFunction(
      isolate, target, isolate->factory()->InternalizeUtf8String(name), type,
      instance_size, inobject_properties, prototype, call, len, adapt);
}

// This sets a constructor instance type on the constructor map which will be
// used in IsXxxConstructor() predicates. Having such predicates helps figuring
// out if a protector cell should be invalidated. If there are no protector
// cell checks required for constructor, this function must not be used.
// Note, this function doesn't create a copy of the constructor's map. So it's
// better to set constructor instance type after all the properties are added
// to the constructor and thus the map is already guaranteed to be unique.
V8_NOINLINE void SetConstructorInstanceType(
    Isolate* isolate, DirectHandle<JSFunction> constructor,
    InstanceType constructor_type) {
  DCHECK(InstanceTypeChecker::IsJSFunction(constructor_type));
  DCHECK_NE(constructor_type, JS_FUNCTION_TYPE);

  Tagged<Map> map = constructor->map();

  // Check we don't accidentally change one of the existing maps.
  DCHECK_NE(map, *isolate->strict_function_map());
  DCHECK_NE(map, *isolate->strict_function_with_readonly_prototype_map());
  // Constructor function map is always a root map, and thus we don't have to
  // deal with updating the whole transition tree.
  DCHECK(IsUndefined(map->GetBackPointer(), isolate));
  DCHECK_EQ(JS_FUNCTION_TYPE, map->instance_type());

  map->set_instance_type(constructor_type);
}

V8_NOINLINE Handle<JSFunction> SimpleCreateFunction(Isolate* isolate,
                                                    Handle<String> name,
                                                    Builtin call, int len,
                                                    AdaptArguments adapt) {
  DCHECK(Builtins::HasJSLinkage(call));
  name = String::Flatten(isolate, name, AllocationType::kOld);
  Handle<JSFunction> fun =
      CreateFunctionForBuiltinWithoutPrototype(isolate, name, call, len, adapt);
  // Make the resulting JSFunction object fast.
  JSObject::MakePrototypesFast(fun, kStartAtReceiver, isolate);
  fun->shared()->set_native(true);
  return fun;
}

V8_NOINLINE Handle<JSFunction> InstallFunctionWithBuiltinId(
    Isolate* isolate, Handle<JSObject> base, const char* name, Builtin call,
    int len, AdaptArguments adapt) {
  Handle<String> internalized_name =
      isolate->factory()->InternalizeUtf8String(name);
  Handle<JSFunction> fun =
      SimpleCreateFunction(isolate, internalized_name, call, len, adapt);
  JSObject::AddProperty(isolate, base, internalized_name, fun, DONT_ENUM);
  return fun;
}

V8_NOINLINE Handle<JSFunction> InstallFunctionAtSymbol(
    Isolate* isolate, Handle<JSObject> base, Handle<Symbol> symbol,
    const char* symbol_string, Builtin call, int len, AdaptArguments adapt,
    PropertyAttributes attrs = DONT_ENUM) {
  Handle<String> internalized_symbol =
      isolate->factory()->InternalizeUtf8String(symbol_string);
  Handle<JSFunction> fun =
      SimpleCreateFunction(isolate, internalized_symbol, call, len, adapt);
  JSObject::AddProperty(isolate, base, symbol, fun, attrs);
  return fun;
}

V8_NOINLINE Handle<JSFunction> CreateSharedObjectConstructor(
    Isolate* isolate, Handle<String> name, DirectHandle<Map> instance_map,
    Builtin builtin, int len, AdaptArguments adapt) {
  Factory* factory = isolate->factory();
  Handle<SharedFunctionInfo> info =
      factory->NewSharedFunctionInfoForBuiltin(name, builtin, len, adapt);
  info->set_language_mode(LanguageMode::kStrict);
  Handle<JSFunction> constructor =
      Factory::JSFunctionBuilder{isolate, info, isolate->native_context()}
          .set_map(isolate->strict_function_with_readonly_prototype_map())
          .Build();
  constructor->set_prototype_or_initial_map(*instance_map, kReleaseStore);

  JSObject::AddProperty(
      isolate, constructor, factory->has_instance_symbol(),
      handle(isolate->native_context()->shared_space_js_object_has_instance(),
             isolate),
      static_cast<PropertyAttributes>(DONT_ENUM | DONT_DELETE | READ_ONLY));
  return constructor;
}

V8_NOINLINE void SimpleInstallGetterSetter(Isolate* isolate,
                                           Handle<JSObject> base,
                                           Handle<Name> name,
                                           Builtin call_getter,
                                           Builtin call_setter) {
  Handle<String> getter_name =
      Name::ToFunctionName(isolate, name, isolate->factory()->get_string())
          .ToHandleChecked();
  DirectHandle<JSFunction> getter =
      SimpleCreateFunction(isolate, getter_name, call_getter, 0, kAdapt);

  Handle<String> setter_name =
      Name::ToFunctionName(isolate, name, isolate->factory()->set_string())
          .ToHandleChecked();
  DirectHandle<JSFunction> setter =
      SimpleCreateFunction(isolate, setter_name, call_setter, 1, kAdapt);

  JSObject::DefineOwnAccessorIgnoreAttributes(base, name, getter, setter,
                                              DONT_ENUM)
      .Check();
}

void SimpleInstallGetterSetter(Isolate* isolate, Handle<JSObject> base,
                               const char* name, Builtin call_getter,
                               Builtin call_setter) {
  SimpleInstallGetterSetter(isolate, base,
                            isolate->factory()->InternalizeUtf8String(name),
                            call_getter, call_setter);
}

V8_NOINLINE Handle<JSFunction> SimpleInstallGetter(
    Isolate* isolate, Handle<JSObject> base, Handle<Name> name,
    Handle<Name> property_name, Builtin call, AdaptArguments adapt) {
  Handle<String> getter_name =
      Name::ToFunctionName(isolate, name, isolate->factory()->get_string())
          .ToHandleChecked();
  Handle<JSFunction> getter =
      SimpleCreateFunction(isolate, getter_name, call, 0, adapt);

  DirectHandle<Object> setter = isolate->factory()->undefined_value();

  JSObject::DefineOwnAccessorIgnoreAttributes(base, property_name, getter,
                                              setter, DONT_ENUM)
      .Check();

  return getter;
}

V8_NOINLINE Handle<JSFunction> SimpleInstallGetter(Isolate* isolate,
                                                   Handle<JSObject> base,
                                                   Handle<Name> name,
                                                   Builtin call,
                                                   AdaptArguments adapt) {
  return SimpleInstallGetter(isolate, base, name, name, call, adapt);
}

V8_NOINLINE void InstallConstant(Isolate* isolate, Handle<JSObject> holder,
                                 const char* name, DirectHandle<Object> value) {
  JSObject::AddProperty(
      isolate, holder, isolate->factory()->InternalizeUtf8String(name), value,
      static_cast<PropertyAttributes>(DONT_DELETE | DONT_ENUM | READ_ONLY));
}

V8_NOINLINE void InstallTrueValuedProperty(Isolate* isolate,
                                           Handle<JSObject> holder,
                                           const char* name) {
  JSObject::AddProperty(isolate, holder,
                        isolate->factory()->InternalizeUtf8String(name),
                        isolate->factory()->true_value(), NONE);
}

V8_NOINLINE void InstallSpeciesGetter(Isolate* isolate,
                                      Handle<JSFunction> constructor) {
  Factory* factory = isolate->factory();
  // TODO(adamk): We should be able to share a SharedFunctionInfo
  // between all these JSFunctins.
  SimpleInstallGetter(isolate, constructor, factory->symbol_species_string(),
                      factory->species_symbol(), Builtin::kReturnReceiver,
                      kAdapt);
}

V8_NOINLINE void InstallToStringTag(Isolate* isolate, Handle<JSObject> holder,
                                    DirectHandle<String> value) {
  JSObject::AddProperty(isolate, holder,
                        isolate->factory()->to_string_tag_symbol(), value,
                        static_cast<PropertyAttributes>(DONT_ENUM | READ_ONLY));
}

void InstallToStringTag(Isolate* isolate, Handle<JSObject> holder,
                        const char* value) {
  InstallToStringTag(isolate, holder,
                     isolate->factory()->InternalizeUtf8String(value));
}

// Create a map for result objects returned from builtins in such a way that
// it's exactly the same map as the one produced by object literals. E.g.,
// iterator result objects have the same map as literals in the form `{value,
// done}`.
//
// This way we have better sharing of maps (i.e. less polymorphism) and also
// make it possible to hit the fast-paths in various builtins (i.e. promises and
// collections) with user defined iterators.
template <size_t N>
Handle<Map> CreateLiteralObjectMapFromCache(
    Isolate* isolate, const std::array<Handle<Name>, N>& properties) {
  Factory* factory = isolate->factory();
  DirectHandle<NativeContext> native_context = isolate->native_context();
  Handle<Map> map = factory->ObjectLiteralMapFromCache(native_context, N);
  for (Handle<Name> name : properties) {
    map = Map::CopyWithField(isolate, map, name, FieldType::Any(isolate), NONE,
                             PropertyConstness::kConst,
                             Representation::Tagged(), INSERT_TRANSITION)
              .ToHandleChecked();
  }
  return map;
}

}  // namespace

Handle<JSFunction> Genesis::CreateEmptyFunction() {
  // Allocate the function map first and then patch the prototype later.
  Handle<Map> empty_function_map = factory()->CreateSloppyFunctionMap(
      FUNCTION_WITHOUT_PROTOTYPE, MaybeHandle<JSFunction>());
  empty_function_map->set_is_prototype_map(true);
  DCHECK(!empty_function_map->is_dictionary_map());

  // Allocate the empty function as the prototype for function according to
  // ES#sec-properties-of-the-function-prototype-object
  Handle<JSFunction> empty_function = CreateFunctionForBuiltin(
      isolate(), factory()->empty_string(), empty_function_map,
      Builtin::kEmptyFunction, 0, kDontAdapt);
  empty_function_map->SetConstructor(*empty_function);
  native_context()->set_empty_function(*empty_function);

  // --- E m p t y ---
  DirectHandle<String> source = factory()->InternalizeString("() {}");
  DirectHandle<Script> script = factory()->NewScript(source);
  script->set_type(Script::Type::kNative);
  DirectHandle<WeakFixedArray> infos = factory()->NewWeakFixedArray(2);
  script->set_infos(*infos);
  ReadOnlyRoots roots{isolate()};
  Tagged<SharedFunctionInfo> sfi = empty_function->shared();
  sfi->set_raw_scope_info(roots.empty_function_scope_info());
  sfi->SetScript(isolate(), roots, *script, 1);
  sfi->UpdateFunctionMapIndex();

  return empty_function;
}

void Genesis::CreateSloppyModeFunctionMaps(Handle<JSFunction> empty) {
  Factory* factory = isolate_->factory();
  DirectHandle<Map> map;

  //
  // Allocate maps for sloppy functions without prototype.
  //
  map = factory->CreateSloppyFunctionMap(FUNCTION_WITHOUT_PROTOTYPE, empty);
  native_context()->set_sloppy_function_without_prototype_map(*map);

  //
  // Allocate maps for sloppy functions with readonly prototype.
  //
  map =
      factory->CreateSloppyFunctionMap(FUNCTION_WITH_READONLY_PROTOTYPE, empty);
  native_context()->set_sloppy_function_with_readonly_prototype_map(*map);

  //
  // Allocate maps for sloppy functions with writable prototype.
  //
  map = factory->CreateSloppyFunctionMap(FUNCTION_WITH_WRITEABLE_PROTOTYPE,
                                         empty);
  native_context()->set_sloppy_function_map(*map);

  map = factory->CreateSloppyFunctionMap(
      FUNCTION_WITH_NAME_AND_WRITEABLE_PROTOTYPE, empty);
  native_context()->set_sloppy_function_with_name_map(*map);
}

DirectHandle<JSFunction> Genesis::GetThrowTypeErrorIntrinsic() {
  if (!restricted_properties_thrower_.is_null()) {
    return restricted_properties_thrower_;
  }
  Handle<String> name = factory()->empty_string();
  Handle<JSFunction> function = CreateFunctionForBuiltinWithoutPrototype(
      isolate(), name, Builtin::kStrictPoisonPillThrower, 0, kAdapt);

  // %ThrowTypeError% must have a name property with an empty string value. Per
  // spec, ThrowTypeError's name is non-configurable, unlike ordinary functions'
  // name property. To redefine it to be non-configurable, use
  // SetOwnPropertyIgnoreAttributes.
  JSObject::SetOwnPropertyIgnoreAttributes(
      function, factory()->name_string(), factory()->empty_string(),
      static_cast<PropertyAttributes>(DONT_ENUM | DONT_DELETE | READ_ONLY))
      .Assert();

  // length needs to be non configurable.
  Handle<Object> value(Smi::FromInt(function->length()), isolate());
  JSObject::SetOwnPropertyIgnoreAttributes(
      function, factory()->length_string(), value,
      static_cast<PropertyAttributes>(DONT_ENUM | DONT_DELETE | READ_ONLY))
      .Assert();

  if (JSObject::PreventExtensions(isolate_, function, kThrowOnError)
          .IsNothing()) {
    DCHECK(false);
  }

  JSObject::MigrateSlowToFast(function, 0, "Bootstrapping");

  restricted_properties_thrower_ = function;
  return function;
}

void Genesis::CreateStrictModeFunctionMaps(Handle<JSFunction> empty) {
  Factory* factory = isolate_->factory();
  DirectHandle<Map> map;

  //
  // Allocate maps for strict functions without prototype.
  //
  map = factory->CreateStrictFunctionMap(FUNCTION_WITHOUT_PROTOTYPE, empty);
  native_context()->set_strict_function_without_prototype_map(*map);

  map = factory->CreateStrictFunctionMap(METHOD_WITH_NAME, empty);
  native_context()->set_method_with_name_map(*map);

  //
  // Allocate maps for strict functions with writable prototype.
  //
  map = factory->CreateStrictFunctionMap(FUNCTION_WITH_WRITEABLE_PROTOTYPE,
                                         empty);
  native_context()->set_strict_function_map(*map);

  map = factory->CreateStrictFunctionMap(
      FUNCTION_WITH_NAME_AND_WRITEABLE_PROTOTYPE, empty);
  native_context()->set_strict_function_with_name_map(*map);

  //
  // Allocate maps for strict functions with readonly prototype.
  //
  map =
      factory->CreateStrictFunctionMap(FUNCTION_WITH_READONLY_PROTOTYPE, empty);
  native_context()->set_strict_function_with_readonly_prototype_map(*map);

  //
  // Allocate map for class functions.
  //
  map = factory->CreateClassFunctionMap(empty);
  native_context()->set_class_function_map(*map);

  // Now that the strict mode function map is available, set up the
  // restricted "arguments" and "caller" getters.
  AddRestrictedFunctionProperties(empty);
}

void Genesis::CreateObjectFunction(DirectHandle<JSFunction> empty_function) {
  Factory* factory = isolate_->factory();

  // --- O b j e c t ---
  int inobject_properties = JSObject::kInitialGlobalObjectUnusedPropertiesCount;
  int instance_size = JSObject::kHeaderSize + kTaggedSize * inobject_properties;

  DirectHandle<JSFunction> object_fun =
      CreateFunction(isolate_, factory->Object_string(), JS_OBJECT_TYPE,
                     instance_size, inobject_properties, factory->null_value(),
                     Builtin::kObjectConstructor, 1, kDontAdapt);
  native_context()->set_object_function(*object_fun);

  {
    // Finish setting up Object function's initial map.
    Tagged<Map> initial_map = object_fun->initial_map();
    initial_map->set_elements_kind(HOLEY_ELEMENTS);
  }

  // Allocate a new prototype for the object function.
  Handle<JSObject> object_function_prototype =
      factory->NewFunctionPrototype(object_fun);

  {
    DirectHandle<Map> map = Map::Copy(
        isolate(), handle(object_function_prototype->map(), isolate()),
        "EmptyObjectPrototype");
    map->set_is_prototype_map(true);
    // Ban re-setting Object.prototype.__proto__ to prevent Proxy security bug
    map->set_is_immutable_proto(true);
    object_function_prototype->set_map(isolate(), *map);
  }

  // Complete setting up empty function.
  {
    DirectHandle<Map> empty_function_map(empty_function->map(), isolate_);
    Map::SetPrototype(isolate(), empty_function_map, object_function_prototype);
  }

  native_context()->set_initial_object_prototype(*object_function_prototype);
  JSFunction::SetPrototype(object_fun, object_function_prototype);
  object_function_prototype->map()->set_instance_type(JS_OBJECT_PROTOTYPE_TYPE);
  {
    // Set up slow map for Object.create(null) instances without in-object
    // properties.
    Handle<Map> map(object_fun->initial_map(), isolate_);
    map = Map::CopyInitialMapNormalized(isolate(), map);
    Map::SetPrototype(isolate(), map, factory->null_value());
    native_context()->set_slow_object_with_null_prototype_map(*map);

    // Set up slow map for literals with too many properties.
    map = Map::Copy(isolate(), map, "slow_object_with_object_prototype_map");
    Map::SetPrototype(isolate(), map, object_function_prototype);
    native_context()->set_slow_object_with_object_prototype_map(*map);
  }
}

namespace {

Handle<Map> CreateNonConstructorMap(Isolate* isolate, Handle<Map> source_map,
                                    Handle<JSObject> prototype,
                                    const char* reason) {
  Handle<Map> map = Map::Copy(isolate, source_map, reason);
  // Ensure the resulting map has prototype slot (it is necessary for storing
  // inital map even when the prototype property is not required).
  if (!map->has_prototype_slot()) {
    // Re-set the unused property fields after changing the instance size.
    int unused_property_fields = map->UnusedPropertyFields();
    map->set_instance_size(map->instance_size() + kTaggedSize);
    // The prototype slot shifts the in-object properties area by one slot.
    map->SetInObjectPropertiesStartInWords(
        map->GetInObjectPropertiesStartInWords() + 1);
    map->set_has_prototype_slot(true);
    map->SetInObjectUnusedPropertyFields(unused_property_fields);
  }
  map->set_is_constructor(false);
  Map::SetPrototype(isolate, map, prototype);
  return map;
}

}  // namespace

Handle<JSFunction> SimpleInstallFunction(Isolate* isolate,
                                         Handle<JSObject> base,
                                         const char* name, Builtin call,
                                         int len, AdaptArguments adapt,
                                         PropertyAttributes attrs) {
  // Although function name does not have to be internalized the property name
  // will be internalized during property addition anyway, so do it here now.
  Handle<String> internalized_name =
      isolate->factory()->InternalizeUtf8String(name);
  Handle<JSFunction> fun =
      SimpleCreateFunction(isolate, internalized_name, call, len, adapt);
  JSObject::AddProperty(isolate, base, internalized_name, fun, attrs);
  return fun;
}

void Genesis::CreateIteratorMaps(Handle<JSFunction> empty) {
  // Create iterator-related meta-objects.
  Handle<JSObject> iterator_prototype = factory()->NewJSObject(
      isolate()->object_function(), AllocationType::kOld);

  InstallFunctionAtSymbol(isolate(), iterator_prototype,
                          factory()->iterator_symbol(), "[Symbol.iterator]",
                          Builtin::kReturnReceiver, 0, kAdapt);
  native_context()->set_initial_iterator_prototype(*iterator_prototype);
  CHECK_NE(iterator_prototype->map().ptr(),
           isolate_->initial_object_prototype()->map().ptr());
  iterator_prototype->map()->set_instance_type(JS_ITERATOR_PROTOTYPE_TYPE);

  Handle<JSObject> generator_object_prototype = factory()->NewJSObject(
      isolate()->object_function(), AllocationType::kOld);
  native_context()->set_initial_generator_prototype(
      *generator_object_prototype);
  JSObject::ForceSetPrototype(isolate(), generator_object_prototype,
                              iterator_prototype);
  Handle<JSObject> generator_function_prototype = factory()->NewJSObject(
      isolate()->object_function(), AllocationType::kOld);
  JSObject::ForceSetPrototype(isolate(), generator_function_prototype, empty);

  InstallToStringTag(isolate(), generator_function_prototype,
                     "GeneratorFunction");
  JSObject::AddProperty(isolate(), generator_function_prototype,
                        factory()->prototype_string(),
                        generator_object_prototype,
                        static_cast<PropertyAttributes>(DONT_ENUM | READ_ONLY));

  JSObject::AddProperty(isolate(), generator_object_prototype,
                        factory()->constructor_string(),
                        generator_function_prototype,
                        static_cast<PropertyAttributes>(DONT_ENUM | READ_ONLY));
  InstallToStringTag(isolate(), generator_object_prototype, "Generator");
  SimpleInstallFunction(isolate(), generator_object_prototype, "next",
                        Builtin::kGeneratorPrototypeNext, 1, kDontAdapt);
  SimpleInstallFunction(isolate(), generator_object_prototype, "return",
                        Builtin::kGeneratorPrototypeReturn, 1, kDontAdapt);
  SimpleInstallFunction(isolate(), generator_object_prototype, "throw",
                        Builtin::kGeneratorPrototypeThrow, 1, kDontAdapt);

  // Internal version of generator_prototype_next, flagged as non-native such
  // that it doesn't show up in Error traces.
  DirectHandle<JSFunction> generator_next_internal =
      SimpleCreateFunction(isolate(), factory()->next_string(),
                           Builtin::kGeneratorPrototypeNext, 1, kDontAdapt);
  generator_next_internal->shared()->set_native(false);
  native_context()->set_generator_next_internal(*generator_next_internal);

  // Internal version of async module functions, flagged as non-native such
  // that they don't show up in Error traces.
  {
    DirectHandle<JSFunction> async_module_evaluate_internal =
        SimpleCreateFunction(isolate(), factory()->next_string(),
                             Builtin::kAsyncModuleEvaluate, 1, kDontAdapt);
    async_module_evaluate_internal->shared()->set_native(false);
    native_context()->set_async_module_evaluate_internal(
        *async_module_evaluate_internal);
  }

  // Create maps for generator functions and their prototypes.  Store those
  // maps in the native context. The "prototype" property descriptor is
  // writable, non-enumerable, and non-configurable (as per ES6 draft
  // 04-14-15, section 25.2.4.3).
  // Generator functions do not have "caller" or "arguments" accessors.
  DirectHandle<Map> map;
  map = CreateNonConstructorMap(isolate(), isolate()->strict_function_map(),
                                generator_function_prototype,
                                "GeneratorFunction");
  native_context()->set_generator_function_map(*map);

  map = CreateNonConstructorMap(
      isolate(), isolate()->strict_function_with_name_map(),
      generator_function_prototype, "GeneratorFunction with name");
  native_context()->set_generator_function_with_name_map(*map);

  DirectHandle<JSFunction> object_function(native_context()->object_function(),
                                           isolate());
  DirectHandle<Map> generator_object_prototype_map = Map::Create(isolate(), 0);
  Map::SetPrototype(isolate(), generator_object_prototype_map,
                    generator_object_prototype);
  native_context()->set_generator_object_prototype_map(
      *generator_object_prototype_map);
}

void Genesis::CreateAsyncIteratorMaps(Handle<JSFunction> empty) {
  // %AsyncIteratorPrototype%
  // proposal-async-iteration/#sec-asynciteratorprototype
  Handle<JSObject> async_iterator_prototype = factory()->NewJSObject(
      isolate()->object_function(), AllocationType::kOld);

  InstallFunctionAtSymbol(
      isolate(), async_iterator_prototype, factory()->async_iterator_symbol(),
      "[Symbol.asyncIterator]", Builtin::kReturnReceiver, 0, kAdapt);
  native_context()->set_initial_async_iterator_prototype(
      *async_iterator_prototype);

  // %AsyncFromSyncIteratorPrototype%
  // proposal-async-iteration/#sec-%asyncfromsynciteratorprototype%-object
  Handle<JSObject> async_from_sync_iterator_prototype = factory()->NewJSObject(
      isolate()->object_function(), AllocationType::kOld);
  SimpleInstallFunction(isolate(), async_from_sync_iterator_prototype, "next",
                        Builtin::kAsyncFromSyncIteratorPrototypeNext, 1,
                        kDontAdapt);
  SimpleInstallFunction(isolate(), async_from_sync_iterator_prototype, "return",
                        Builtin::kAsyncFromSyncIteratorPrototypeReturn, 1,
                        kDontAdapt);
  SimpleInstallFunction(isolate(), async_from_sync_iterator_prototype, "throw",
                        Builtin::kAsyncFromSyncIteratorPrototypeThrow, 1,
                        kDontAdapt);

  InstallToStringTag(isolate(), async_from_sync_iterator_prototype,
                     "Async-from-Sync Iterator");

  JSObject::ForceSetPrototype(isolate(), async_from_sync_iterator_prototype,
                              async_iterator_prototype);

  DirectHandle<Map> async_from_sync_iterator_map =
      factory()->NewContextfulMapForCurrentContext(
          JS_ASYNC_FROM_SYNC_ITERATOR_TYPE,
          JSAsyncFromSyncIterator::kHeaderSize);
  Map::SetPrototype(isolate(), async_from_sync_iterator_map,
                    async_from_sync_iterator_prototype);
  native_context()->set_async_from_sync_iterator_map(
      *async_from_sync_iterator_map);

  // Async Generators
  Handle<JSObject> async_generator_object_prototype = factory()->NewJSObject(
      isolate()->object_function(), AllocationType::kOld);
  Handle<JSObject> async_generator_function_prototype = factory()->NewJSObject(
      isolate()->object_function(), AllocationType::kOld);

  // %AsyncGenerator% / %AsyncGeneratorFunction%.prototype
  JSObject::ForceSetPrototype(isolate(), async_generator_function_prototype,
                              empty);

  // The value of AsyncGeneratorFunction.prototype.prototype is the
  //     %AsyncGeneratorPrototype% intrinsic object.
  // This property has the attributes
  //     { [[Writable]]: false, [[Enumerable]]: false, [[Configurable]]: true }.
  JSObject::AddProperty(isolate(), async_generator_function_prototype,
                        factory()->prototype_string(),
                        async_generator_object_prototype,
                        static_cast<PropertyAttributes>(DONT_ENUM | READ_ONLY));
  JSObject::AddProperty(isolate(), async_generator_object_prototype,
                        factory()->constructor_string(),
                        async_generator_function_prototype,
                        static_cast<PropertyAttributes>(DONT_ENUM | READ_ONLY));
  InstallToStringTag(isolate(), async_generator_function_prototype,
                     "AsyncGeneratorFunction");

  // %AsyncGeneratorPrototype%
  JSObject::ForceSetPrototype(isolate(), async_generator_object_prototype,
                              async_iterator_prototype);
  native_context()->set_initial_async_generator_prototype(
      *async_generator_object_prototype);

  InstallToStringTag(isolate(), async_generator_object_prototype,
                     "AsyncGenerator");
  SimpleInstallFunction(isolate(), async_generator_object_prototype, "next",
                        Builtin::kAsyncGeneratorPrototypeNext, 1, kDontAdapt);
  SimpleInstallFunction(isolate(), async_generator_object_prototype, "return",
                        Builtin::kAsyncGeneratorPrototypeReturn, 1, kDontAdapt);
  SimpleInstallFunction(isolate(), async_generator_object_prototype, "throw",
                        Builtin::kAsyncGeneratorPrototypeThrow, 1, kDontAdapt);

  // Create maps for generator functions and their prototypes.  Store those
  // maps in the native context. The "prototype" property descriptor is
  // writable, non-enumerable, and non-configurable (as per ES6 draft
  // 04-14-15, section 25.2.4.3).
  // Async Generator functions do not have "caller" or "arguments" accessors.
  DirectHandle<Map> map;
  map = CreateNonConstructorMap(isolate(), isolate()->strict_function_map(),
                                async_generator_function_prototype,
                                "AsyncGeneratorFunction");
  native_context()->set_async_generator_function_map(*map);

  map = CreateNonConstructorMap(
      isolate(), isolate()->strict_function_with_name_map(),
      async_generator_function_prototype, "AsyncGeneratorFunction with name");
  native_context()->set_async_generator_function_with_name_map(*map);

  DirectHandle<JSFunction> object_function(native_context()->object_function(),
                                           isolate());
  DirectHandle<Map> async_generator_object_prototype_map =
      Map::Create(isolate(), 0);
  Map::SetPrototype(isolate(), async_generator_object_prototype_map,
                    async_generator_object_prototype);
  native_context()->set_async_generator_object_prototype_map(
      *async_generator_object_prototype_map);
}

void Genesis::CreateAsyncFunctionMaps(Handle<JSFunction> empty) {
  // %AsyncFunctionPrototype% intrinsic
  Handle<JSObject> async_function_prototype = factory()->NewJSObject(
      isolate()->object_function(), AllocationType::kOld);
  JSObject::ForceSetPrototype(isolate(), async_function_prototype, empty);

  InstallToStringTag(isolate(), async_function_prototype, "AsyncFunction");

  DirectHandle<Map> map =
      Map::Copy(isolate(), isolate()->strict_function_without_prototype_map(),
                "AsyncFunction");
  Map::SetPrototype(isolate(), map, async_function_prototype);
  native_context()->set_async_function_map(*map);

  map = Map::Copy(isolate(), isolate()->method_with_name_map(),
                  "AsyncFunction with name");
  Map::SetPrototype(isolate(), map, async_function_prototype);
  native_context()->set_async_function_with_name_map(*map);
}

void Genesis::CreateJSProxyMaps() {
  // Allocate maps for all Proxy types.
  // Next to the default proxy, we need maps indicating callable and
  // constructable proxies.
  Handle<Map> proxy_map = factory()->NewContextfulMapForCurrentContext(
      JS_PROXY_TYPE, JSProxy::kSize, TERMINAL_FAST_ELEMENTS_KIND);
  proxy_map->set_is_dictionary_map(true);
  proxy_map->set_may_have_interesting_properties(true);
  native_context()->set_proxy_map(*proxy_map);
  proxy_map->SetConstructor(native_context()->object_function());

  Handle<Map> proxy_callable_map =
      Map::Copy(isolate_, proxy_map, "callable Proxy");
  proxy_callable_map->set_is_callable(true);
  native_context()->set_proxy_callable_map(*proxy_callable_map);
  proxy_callable_map->SetConstructor(native_context()->function_function());

  DirectHandle<Map> proxy_constructor_map =
      Map::Copy(isolate_, proxy_callable_map, "constructor Proxy");
  proxy_constructor_map->set_is_constructor(true);
  native_context()->set_proxy_constructor_map(*proxy_constructor_map);

  {
    DirectHandle<Map> map = factory()->NewContextfulMapForCurrentContext(
        JS_OBJECT_TYPE, JSProxyRevocableResult::kSize,
        TERMINAL_FAST_ELEMENTS_KIND, 2);
    Map::EnsureDescriptorSlack(isolate_, map, 2);

    {  // proxy
      Descriptor d = Descriptor::DataField(isolate(), factory()->proxy_string(),
                                           JSProxyRevocableResult::kProxyIndex,
                                           NONE, Representation::Tagged());
      map->AppendDescriptor(isolate(), &d);
    }
    {  // revoke
      Descriptor d = Descriptor::DataField(
          isolate(), factory()->revoke_string(),
          JSProxyRevocableResult::kRevokeIndex, NONE, Representation::Tagged());
      map->AppendDescriptor(isolate(), &d);
    }

    Map::SetPrototype(isolate(), map, isolate()->initial_object_prototype());
    map->SetConstructor(native_context()->object_function());

    native_context()->set_proxy_revocable_result_map(*map);
  }
}

namespace {
void ReplaceAccessors(Isolate* isolate, DirectHandle<Map> map,
                      Handle<String> name, PropertyAttributes attributes,
                      Handle<AccessorPair> accessor_pair) {
  Tagged<DescriptorArray> descriptors = map->instance_descriptors(isolate);
  InternalIndex entry = descriptors->SearchWithCache(isolate, *name, *map);
  Descriptor d = Descriptor::AccessorConstant(name, accessor_pair, attributes);
  descriptors->Replace(entry, &d);
}

void InitializeJSArrayMaps(Isolate* isolate,
                           DirectHandle<Context> native_context,
                           Handle<Map> initial_map) {
  // Replace all of the cached initial array maps in the native context with
  // the appropriate transitioned elements kind maps.
  Handle<Map> current_map = initial_map;
  ElementsKind kind = current_map->elements_kind();
  DCHECK_EQ(GetInitialFastElementsKind(), kind);
  DCHECK_EQ(PACKED_SMI_ELEMENTS, kind);
  DCHECK_EQ(Context::ArrayMapIndex(kind),
            Context::JS_ARRAY_PACKED_SMI_ELEMENTS_MAP_INDEX);
  native_context->set(Context::ArrayMapIndex(kind), *current_map,
                      UPDATE_WRITE_BARRIER, kReleaseStore);
  for (int i = GetSequenceIndexFromFastElementsKind(kind) + 1;
       i < kFastElementsKindCount; ++i) {
    Handle<Map> new_map;
    ElementsKind next_kind = GetFastElementsKindFromSequenceIndex(i);
    Tagged<Map> maybe_elements_transition = current_map->ElementsTransitionMap(
        isolate, ConcurrencyMode::kSynchronous);
    if (!maybe_elements_transition.is_null()) {
      new_map = handle(maybe_elements_transition, isolate);
    } else {
      new_map = Map::CopyAsElementsKind(isolate, current_map, next_kind,
                                        INSERT_TRANSITION);
    }
    DCHECK_EQ(next_kind, new_map->elements_kind());
    native_context->set(Context::ArrayMapIndex(next_kind), *new_map,
                        UPDATE_WRITE_BARRIER, kReleaseStore);
    current_map = new_map;
  }
}
}  // namespace

void Genesis::AddRestrictedFunctionProperties(DirectHandle<JSFunction> empty) {
  PropertyAttributes rw_attribs = static_cast<PropertyAttributes>(DONT_ENUM);
  DirectHandle<JSFunction> thrower = GetThrowTypeErrorIntrinsic();
  Handle<AccessorPair> accessors = factory()->NewAccessorPair();
  accessors->set_getter(*thrower);
  accessors->set_setter(*thrower);

  DirectHandle<Map> map(empty->map(), isolate());
  ReplaceAccessors(isolate(), map, factory()->arguments_string(), rw_attribs,
                   accessors);
  ReplaceAccessors(isolate(), map, factory()->caller_string(), rw_attribs,
                   accessors);
}

static void AddToWeakNativeContextList(Isolate* isolate,
                                       Tagged<Context> context) {
  DCHECK(IsNativeContext(context));
  Heap* heap = isolate->heap();
#ifdef DEBUG
  {
    DCHECK(IsUndefined(context->next_context_link(), isolate));
    // Check that context is not in the list yet.
    for (Tagged<Object> current = heap->native_contexts_list();
         !IsUndefined(current, isolate);
         current = Cast<Context>(current)->next_context_link()) {
      DCHECK(current != context);
    }
  }
#endif
  context->set(Context::NEXT_CONTEXT_LINK, heap->native_contexts_list(),
               UPDATE_WRITE_BARRIER);
  heap->set_native_contexts_list(context);
}

void Genesis::CreateRoots() {
  // Allocate the native context FixedArray first and then patch the
  // closure and extension object later (we need the empty function
  // and the global object, but in order to create those, we need the
  // native context).
  native_context_ = factory()->NewNativeContext();

  AddToWeakNativeContextList(isolate(), *native_context());
  isolate()->set_context(*native_context());
}

void Genesis::InstallGlobalThisBinding() {
  DirectHandle<ScopeInfo> scope_info =
      ReadOnlyRoots(isolate()).global_this_binding_scope_info_handle();
  DirectHandle<Context> context =
      factory()->NewScriptContext(native_context(), scope_info);

  // Go ahead and hook it up while we're at it.
  int slot = scope_info->ReceiverContextSlotIndex();
  DCHECK_EQ(slot, Context::MIN_CONTEXT_EXTENDED_SLOTS);
  context->set(slot, native_context()->global_proxy());

  Handle<ScriptContextTable> script_contexts(
      native_context()->script_context_table(), isolate());
  DirectHandle<ScriptContextTable> new_script_contexts =
      ScriptContextTable::Add(isolate(), script_contexts, context, false);
  native_context()->set_script_context_table(*new_script_contexts);
}

Handle<JSGlobalObject> Genesis::CreateNewGlobals(
    v8::Local<v8::ObjectTemplate> global_proxy_template,
    DirectHandle<JSGlobalProxy> global_proxy) {
  // The argument global_proxy_template aka data is an ObjectTemplateInfo.
  // It has a constructor pointer that points at global_constructor which is a
  // FunctionTemplateInfo.
  // The global_proxy_constructor is used to (re)initialize the
  // global_proxy. The global_proxy_constructor also has a prototype_template
  // pointer that points at js_global_object_template which is an
  // ObjectTemplateInfo.
  // That in turn has a constructor pointer that points at
  // js_global_object_constructor which is a FunctionTemplateInfo.
  // js_global_object_constructor is used to make js_global_object_function
  // js_global_object_function is used to make the new global_object.
  //
  // --- G l o b a l ---
  // Step 1: Create a fresh JSGlobalObject.
  DirectHandle<JSFunction> js_global_object_function;
  Handle<ObjectTemplateInfo> js_global_object_template;
  if (!global_proxy_template.IsEmpty()) {
    // Get prototype template of the global_proxy_template.
    DirectHandle<ObjectTemplateInfo> data =
        v8::Utils::OpenDirectHandle(*global_proxy_template);
    DirectHandle<FunctionTemplateInfo> global_constructor(
        Cast<FunctionTemplateInfo>(data->constructor()), isolate());
    Handle<Object> proto_template(global_constructor->GetPrototypeTemplate(),
                                  isolate());
    if (!IsUndefined(*proto_template, isolate())) {
      js_global_object_template = Cast<ObjectTemplateInfo>(proto_template);
    }
  }

  if (js_global_object_template.is_null()) {
    Handle<String> name = factory()->empty_string();
    Handle<JSObject> prototype =
        factory()->NewFunctionPrototype(isolate()->object_function());
    js_global_object_function = CreateFunctionForBuiltinWithPrototype(
        isolate(), name, Builtin::kIllegal, prototype, JS_GLOBAL_OBJECT_TYPE,
        JSGlobalObject::kHeaderSize, 0, MUTABLE, 0, kDontAdapt);
#ifdef DEBUG
    LookupIterator it(isolate(), prototype, factory()->constructor_string(),
                      LookupIterator::OWN_SKIP_INTERCEPTOR);
    DirectHandle<Object> value = Object::GetProperty(&it).ToHandleChecked();
    DCHECK(it.IsFound());
    DCHECK_EQ(*isolate()->object_function(), *value);
#endif
  } else {
    DirectHandle<FunctionTemplateInfo> js_global_object_constructor(
        Cast<FunctionTemplateInfo>(js_global_object_template->constructor()),
        isolate());
    js_global_object_function = ApiNatives::CreateApiFunction(
        isolate(), isolate()->native_context(), js_global_object_constructor,
        factory()->the_hole_value(), JS_GLOBAL_OBJECT_TYPE);
  }

  js_global_object_function->initial_map()->set_is_prototype_map(true);
  js_global_object_function->initial_map()->set_is_dictionary_map(true);
  js_global_object_function->initial_map()->set_may_have_interesting_properties(
      true);
  Handle<JSGlobalObject> global_object =
      factory()->NewJSGlobalObject(js_global_object_function);

  // Step 2: (re)initialize the global proxy object.
  DirectHandle<JSFunction> global_proxy_function;
  if (global_proxy_template.IsEmpty()) {
    Handle<String> name = factory()->empty_string();
    global_proxy_function = CreateFunctionForBuiltinWithPrototype(
        isolate(), name, Builtin::kIllegal, factory()->the_hole_value(),
        JS_GLOBAL_PROXY_TYPE, JSGlobalProxy::SizeWithEmbedderFields(0), 0,
        MUTABLE, 0, kDontAdapt);
  } else {
    DirectHandle<ObjectTemplateInfo> data =
        v8::Utils::OpenDirectHandle(*global_proxy_template);
    DirectHandle<FunctionTemplateInfo> global_constructor(
        Cast<FunctionTemplateInfo>(data->constructor()), isolate());
    global_proxy_function = ApiNatives::CreateApiFunction(
        isolate(), isolate()->native_context(), global_constructor,
        factory()->the_hole_value(), JS_GLOBAL_PROXY_TYPE);
  }
  global_proxy_function->initial_map()->set_is_access_check_needed(true);
  global_proxy_function->initial_map()->set_may_have_interesting_properties(
      true);
  native_context()->set_global_proxy_function(*global_proxy_function);

  // Set the global object as the (hidden) __proto__ of the global proxy after
  // ConfigureGlobalObject
  factory()->ReinitializeJSGlobalProxy(global_proxy, global_proxy_function);

  // Set up the pointer back from the global object to the global proxy.
  global_object->set_global_proxy(*global_proxy);
  // Set the native context of the global proxy.
  global_proxy->map()->set_map(isolate(), native_context()->meta_map());
  // Set the global proxy of the native context. If the native context has been
  // deserialized, the global proxy is already correctly set up by the
  // deserializer. Otherwise it's undefined.
  DCHECK(IsUndefined(native_context()->get(Context::GLOBAL_PROXY_INDEX),
                     isolate()) ||
         native_context()->global_proxy_object() == *global_proxy);
  native_context()->set_global_proxy_object(*global_proxy);

  return global_object;
}

void Genesis::HookUpGlobalProxy(DirectHandle<JSGlobalProxy> global_proxy) {
  // Re-initialize the global proxy with the global proxy function from the
  // snapshot, and then set up the link to the native context.
  DirectHandle<JSFunction> global_proxy_function(
      native_context()->global_proxy_function(), isolate());
  factory()->ReinitializeJSGlobalProxy(global_proxy, global_proxy_function);
  Handle<JSObject> global_object(
      Cast<JSObject>(native_context()->global_object()), isolate());
  JSObject::ForceSetPrototype(isolate(), global_proxy, global_object);
  global_proxy->map()->set_map(isolate(), native_context()->meta_map());
  DCHECK(native_context()->global_proxy() == *global_proxy);
}

void Genesis::HookUpGlobalObject(Handle<JSGlobalObject> global_object) {
  DirectHandle<JSGlobalObject> global_object_from_snapshot(
      Cast<JSGlobalObject>(native_context()->extension()), isolate());
  native_context()->set_extension(*global_object);
  native_context()->set_security_token(*global_object);

  TransferNamedProperties(global_object_from_snapshot, global_object);
  if (global_object_from_snapshot->HasDictionaryElements()) {
    JSObject::NormalizeElements(global_object);
  }
  DCHECK_EQ(global_object_from_snapshot->GetElementsKind(),
            global_object->GetElementsKind());
  TransferIndexedProperties(global_object_from_snapshot, global_object);
}

// See https://tc39.es/ecma262/#sec-ordinarycreatefromconstructor for details
// about intrinsicDefaultProto concept. In short it's about using proper
// prototype object from constructor's realm when 
"""


```