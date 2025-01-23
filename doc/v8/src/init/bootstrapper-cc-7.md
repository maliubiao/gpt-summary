Response:
My thought process for analyzing the provided V8 source code snippet goes like this:

1. **Understand the Goal:** The request asks for a functional summary of the `bootstrapper.cc` file (specifically a part of it), mentions potential `.tq` files, relates it to JavaScript, asks for examples and logic inference, and finally asks for a summary of the provided section.

2. **Identify the File Type:** The provided snippet is clearly C++ code, not Torque (which would end in `.tq`). This immediately answers the first question about the file extension.

3. **Recognize Key V8 Concepts:**  I scan the code for familiar V8 terms and patterns. I see things like:
    * `Isolate`:  The core V8 instance.
    * `Factory`: Used for creating V8 objects.
    * `HandleScope`: Manages V8 object handles.
    * `Handle<...>`: Smart pointers for V8 objects.
    * `JSObject`, `JSFunction`, `Map`:  Fundamental JavaScript object types in V8.
    * `Builtin::k...`:  References to built-in JavaScript functions implemented in C++.
    * `native_context()`:  The context holding built-in objects and functions.
    * `InstallFunction`, `SimpleInstallFunction`, `InstallConstant`: Functions likely involved in setting up built-in objects and their properties.
    * Specific JavaScript concepts like `Reflect`, `Bound Function`, `FinalizationRegistry`, `WeakRef`, `arguments`, `AsyncFunction`, `GeneratorFunction`, `Iterator`.

4. **Group Related Code Blocks:** I notice distinct sections within the code, often separated by comments like `// --- Reflect`, `// --- BoundFunction`, etc. Each section seems to be responsible for initializing a specific JavaScript feature or object. This helps in breaking down the complexity.

5. **Infer Functionality of Each Section:** Based on the V8 concepts and the names of the JavaScript features being initialized, I can infer the purpose of each code block:
    * **Reflect:** Setting up the `Reflect` built-in object and its methods.
    * **Bound Function:**  Creating the internal representation of bound functions (using `bind()`).
    * **FinalizationRegistry:** Implementing the `FinalizationRegistry` for weak references and finalization callbacks.
    * **WeakRef:**  Implementing the `WeakRef` for weak references to objects.
    * **Sloppy/Strict Arguments:**  Creating the special `arguments` object in both sloppy and strict modes.
    * **Context Extension:** Setting up objects used for the `with` statement (context extension).
    * **Call Delegates:** Setting up functions that handle calling API objects as functions or constructors.

6. **Connect to JavaScript Functionality:**  Since the code is initializing JavaScript built-ins, I can easily connect the C++ code to its corresponding JavaScript functionality. For instance, the "Reflect" section directly relates to the `Reflect` object in JavaScript. The "Bound Function" section relates to the `bind()` method on functions.

7. **Construct JavaScript Examples:** For each initialized feature, I can create simple JavaScript examples demonstrating its usage. This makes the connection between the C++ code and the JavaScript user experience concrete.

8. **Consider Logic and Input/Output (Where Applicable):** While this specific snippet is mostly about initialization rather than complex logic, I consider where logic might be involved. For instance, the `FinalizationRegistry`'s `register` and `unregister` methods imply a registration and unregistration process. I can think of simple input/output scenarios for these.

9. **Identify Potential User Errors:**  Thinking about how these features are used in JavaScript, I can identify common errors users might make. For example, misusing `WeakRef` by assuming the referenced object will always be available, or misunderstanding how `arguments` works in strict mode.

10. **Address Specific Instructions:** I go back to the original request and ensure I've addressed each point:
    * File functionality: Described for each section.
    * `.tq` extension: Confirmed it's not a Torque file.
    * Relationship to JavaScript: Explained and exemplified.
    * Logic/Input-Output: Provided examples where relevant.
    * User errors:  Included common mistakes.
    * Part number: Acknowledged it's part 8/11.
    * Overall Summary: Combine the individual section summaries into a higher-level overview.

11. **Structure the Output:** I organize the information logically, starting with a general overview, then detailing each section, providing JavaScript examples, error examples, and finally the overall summary. This makes the information easier to understand.

By following these steps, I can effectively analyze the provided V8 source code snippet and generate a comprehensive and informative response. The key is to leverage knowledge of V8 internals and their connection to JavaScript language features.
好的，我们来分析一下 `v8/src/init/bootstrapper.cc` 的这段代码片段的功能。

**文件类型判断:**

`v8/src/init/bootstrapper.cc` 以 `.cc` 结尾，这表明它是一个 **C++ 源代码文件**，而不是 Torque 源代码文件（Torque 文件以 `.tq` 结尾）。

**功能列举:**

这段代码的主要功能是 **初始化 V8 引擎的内置对象和函数**，特别关注以下几个方面：

1. **Reflect 对象:**  安装 `Reflect` 对象的各种静态方法，例如 `defineProperty`, `getOwnPropertyDescriptor`, `getPrototypeOf`, `setPrototypeOf` 等。这些方法提供了对对象进行内省和操作的底层能力。

2. **Bound Function (绑定函数):**  设置绑定函数的内部结构和属性，包括其 `length` 和 `name` 属性的访问器。绑定函数是通过 `Function.prototype.bind()` 创建的。

3. **FinalizationRegistry (终结器注册表):**  初始化 `FinalizationRegistry` 构造函数及其原型对象上的方法，如 `register` 和 `unregister`。`FinalizationRegistry` 允许在对象被垃圾回收时执行清理操作。

4. **WeakRef (弱引用):** 初始化 `WeakRef` 构造函数及其原型对象上的方法 `deref`。`WeakRef` 允许创建对对象的弱引用，不会阻止对象被垃圾回收。

5. **Arguments 对象 (实参对象):**  创建和配置 `arguments` 对象的 Map (用于描述对象的结构)。区分了 sloppy mode (非严格模式) 和 strict mode (严格模式) 下的 `arguments` 对象，以及快速和慢速的别名实参对象。

6. **Context Extension (上下文扩展):**  创建一个用于 `with` 语句的上下文扩展对象的构造函数。

7. **Call Delegates (调用委托):**  设置用于处理 API 对象作为函数或构造函数调用的委托函数。

8. **Typed Arrays (类型化数组):**  定义和初始化各种类型化数组的构造函数，例如 `Int8Array`, `Uint8Array` 等，并设置它们的 `BYTES_PER_ELEMENT` 属性。同时也处理了共享数组缓冲区（SharedArrayBuffer，RAB/GSAB）支持的类型化数组的初始化。

**与 Javascript 的关系 (并举例说明):**

这段 C++ 代码直接负责在 V8 引擎启动时创建和配置 JavaScript 中可用的内置对象和功能。以下是一些与 JavaScript 功能对应的例子：

* **Reflect:**
  ```javascript
  const obj = { a: 1 };
  Reflect.defineProperty(obj, 'b', { value: 2 });
  console.log(obj.b); // 输出: 2
  console.log(Reflect.has(obj, 'a')); // 输出: true
  ```

* **Bound Function:**
  ```javascript
  function greet(name) {
    console.log(`Hello, ${name}!`);
  }
  const greetJohn = greet.bind(null, 'John');
  greetJohn(); // 输出: Hello, John!
  console.log(greetJohn.name); // 输出: bound greet
  console.log(greetJohn.length); // 输出: 1 (原始函数的参数个数减去绑定时提供的参数个数)
  ```

* **FinalizationRegistry:**
  ```javascript
  let target = {};
  const registry = new FinalizationRegistry(heldValue => {
    console.log(`Object with value ${heldValue} was garbage collected.`);
  });
  registry.register(target, 'myTarget');
  target = null; // 解除引用，允许垃圾回收
  // 当 target 被垃圾回收时，控制台会输出 "Object with value myTarget was garbage collected."
  ```

* **WeakRef:**
  ```javascript
  let target = {};
  const weakRef = new WeakRef(target);
  console.log(weakRef.deref() === target); // 输出: true
  target = null; // 解除引用
  // 在某个时间点，当 target 被垃圾回收后，weakRef.deref() 将返回 undefined。
  ```

* **Arguments 对象:**
  ```javascript
  function foo(a, b) {
    console.log(arguments[0]); // 输出传入的第一个参数
    console.log(arguments.length); // 输出传入的参数个数
  }
  foo(1, 2, 3);
  ```

* **Typed Arrays:**
  ```javascript
  const buffer = new ArrayBuffer(8);
  const uint32View = new Uint32Array(buffer);
  uint32View[0] = 42;
  console.log(uint32View[0]); // 输出: 42
  ```

**代码逻辑推理 (假设输入与输出):**

这段代码主要是初始化过程，而不是执行用户代码。因此，直接的 "输入输出" 可能不太适用。但是，我们可以考虑在初始化过程中设置的内部状态。

**假设输入:**  V8 引擎开始启动。

**输出 (部分):**

* 创建了全局对象 `Reflect`，并为其添加了诸如 `defineProperty` 等内置函数。
* 创建了 `FinalizationRegistry` 构造函数，并设置了其原型链和方法。
* `native_context` 中存储了 `sloppy_arguments_map` 和 `strict_arguments_map`，用于创建不同模式下的 `arguments` 对象。

**用户常见的编程错误:**

* **错误地使用 `arguments` 对象:** 在严格模式下，`arguments.callee` 和 `arguments.caller` 是被禁用的，尝试访问会抛出 `TypeError`。
  ```javascript
  "use strict";
  function foo() {
    console.log(arguments.callee); // TypeError: 'caller', 'callee', and 'arguments' properties cannot be accessed on strict mode functions or the arguments objects for calls to them
  }
  foo();
  ```

* **误解 `WeakRef` 的生命周期:**  开发者可能会认为只要 `WeakRef` 对象存在，引用的对象就不会被垃圾回收，这是错误的。`WeakRef` 只是一个弱引用，目标对象仍然会根据正常的垃圾回收机制被回收。
  ```javascript
  let target = { value: 1 };
  const weakRef = new WeakRef(target);
  // ... 一段时间后 ...
  if (weakRef.deref()) {
    console.log(weakRef.deref().value); // 可能抛出错误，因为 target 可能已被回收
  }
  ```

* **不恰当的 `FinalizationRegistry` 使用:**  过度依赖终结器进行资源管理可能导致问题，因为终结器的执行时机是不确定的。应该优先使用更可靠的资源管理机制（例如，使用 `try...finally` 或 RAII 模式）。

**归纳功能 (第 8 部分，共 11 部分):**

作为启动过程的第 8 部分，这段代码专注于 **创建和配置一些重要的、相对底层的 JavaScript 内置对象和功能**，例如 `Reflect`、绑定函数、弱引用、终结器注册表以及不同模式下的 `arguments` 对象。它也负责初始化类型化数组的基础结构。这些功能的初始化为后续更高级的 JavaScript 特性和用户代码的执行奠定了基础。可以认为这部分主要关注的是 **元编程和内存管理相关的基础构建块**。

### 提示词
```
这是目录为v8/src/init/bootstrapper.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/init/bootstrapper.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第8部分，共11部分，请归纳一下它的功能
```

### 源代码
```cpp
:kReflectOwnKeys, 1, kAdapt);
    SimpleInstallFunction(isolate_, reflect, "preventExtensions",
                          Builtin::kReflectPreventExtensions, 1, kAdapt);
    SimpleInstallFunction(isolate_, reflect, "set", Builtin::kReflectSet, 3,
                          kDontAdapt);
    SimpleInstallFunction(isolate_, reflect, "setPrototypeOf",
                          Builtin::kReflectSetPrototypeOf, 2, kAdapt);
  }

  {  // --- B o u n d F u n c t i o n
    Handle<Map> map = factory->NewContextfulMapForCurrentContext(
        JS_BOUND_FUNCTION_TYPE, JSBoundFunction::kHeaderSize,
        TERMINAL_FAST_ELEMENTS_KIND, 0);
    map->SetConstructor(native_context()->object_function());
    map->set_is_callable(true);
    Map::SetPrototype(isolate(), map, empty_function);

    PropertyAttributes roc_attribs =
        static_cast<PropertyAttributes>(DONT_ENUM | READ_ONLY);
    Map::EnsureDescriptorSlack(isolate_, map, 2);

    {  // length
      static_assert(
          JSFunctionOrBoundFunctionOrWrappedFunction::kLengthDescriptorIndex ==
          0);
      Descriptor d = Descriptor::AccessorConstant(
          factory->length_string(), factory->bound_function_length_accessor(),
          roc_attribs);
      map->AppendDescriptor(isolate(), &d);
    }

    {  // name
      static_assert(
          JSFunctionOrBoundFunctionOrWrappedFunction::kNameDescriptorIndex ==
          1);
      Descriptor d = Descriptor::AccessorConstant(
          factory->name_string(), factory->bound_function_name_accessor(),
          roc_attribs);
      map->AppendDescriptor(isolate(), &d);
    }
    native_context()->set_bound_function_without_constructor_map(*map);

    map = Map::Copy(isolate_, map, "IsConstructor");
    map->set_is_constructor(true);
    native_context()->set_bound_function_with_constructor_map(*map);
  }

  {  // -- F i n a l i z a t i o n R e g i s t r y
    Handle<JSFunction> finalization_registry_fun = InstallFunction(
        isolate_, global, factory->FinalizationRegistry_string(),
        JS_FINALIZATION_REGISTRY_TYPE, JSFinalizationRegistry::kHeaderSize, 0,
        factory->the_hole_value(), Builtin::kFinalizationRegistryConstructor, 1,
        kDontAdapt);
    InstallWithIntrinsicDefaultProto(
        isolate_, finalization_registry_fun,
        Context::JS_FINALIZATION_REGISTRY_FUNCTION_INDEX);

    Handle<JSObject> finalization_registry_prototype(
        Cast<JSObject>(finalization_registry_fun->instance_prototype()),
        isolate());

    InstallToStringTag(isolate_, finalization_registry_prototype,
                       factory->FinalizationRegistry_string());

    SimpleInstallFunction(isolate_, finalization_registry_prototype, "register",
                          Builtin::kFinalizationRegistryRegister, 2,
                          kDontAdapt);

    SimpleInstallFunction(
        isolate_, finalization_registry_prototype, "unregister",
        Builtin::kFinalizationRegistryUnregister, 1, kDontAdapt);

    // The cleanupSome function is created but not exposed, as it is used
    // internally by InvokeFinalizationRegistryCleanupFromTask.
    //
    // It is exposed by v8_flags.harmony_weak_refs_with_cleanup_some.
    DirectHandle<JSFunction> cleanup_some_fun = SimpleCreateFunction(
        isolate_, factory->InternalizeUtf8String("cleanupSome"),
        Builtin::kFinalizationRegistryPrototypeCleanupSome, 0, kDontAdapt);
    native_context()->set_finalization_registry_cleanup_some(*cleanup_some_fun);
  }

  {  // -- W e a k R e f
    Handle<JSFunction> weak_ref_fun =
        InstallFunction(isolate_, global, "WeakRef", JS_WEAK_REF_TYPE,
                        JSWeakRef::kHeaderSize, 0, factory->the_hole_value(),
                        Builtin::kWeakRefConstructor, 1, kDontAdapt);
    InstallWithIntrinsicDefaultProto(isolate_, weak_ref_fun,
                                     Context::JS_WEAK_REF_FUNCTION_INDEX);

    Handle<JSObject> weak_ref_prototype(
        Cast<JSObject>(weak_ref_fun->instance_prototype()), isolate());

    InstallToStringTag(isolate_, weak_ref_prototype, factory->WeakRef_string());

    SimpleInstallFunction(isolate_, weak_ref_prototype, "deref",
                          Builtin::kWeakRefDeref, 0, kAdapt);
  }

  {  // --- sloppy arguments map
    Handle<String> arguments_string = factory->Arguments_string();
    DirectHandle<JSFunction> function = CreateFunctionForBuiltinWithPrototype(
        isolate(), arguments_string, Builtin::kIllegal,
        isolate()->initial_object_prototype(), JS_ARGUMENTS_OBJECT_TYPE,
        JSSloppyArgumentsObject::kSize, 2, MUTABLE, 0, kDontAdapt);
    DirectHandle<Map> map(function->initial_map(), isolate());

    // Create the descriptor array for the arguments object.
    Map::EnsureDescriptorSlack(isolate_, map, 2);

    {  // length
      Descriptor d =
          Descriptor::DataField(isolate(), factory->length_string(),
                                JSSloppyArgumentsObject::kLengthIndex,
                                DONT_ENUM, Representation::Tagged());
      map->AppendDescriptor(isolate(), &d);
    }
    {  // callee
      Descriptor d =
          Descriptor::DataField(isolate(), factory->callee_string(),
                                JSSloppyArgumentsObject::kCalleeIndex,
                                DONT_ENUM, Representation::Tagged());
      map->AppendDescriptor(isolate(), &d);
    }
    // @@iterator method is added later.

    native_context()->set_sloppy_arguments_map(*map);

    DCHECK(!map->is_dictionary_map());
    DCHECK(IsObjectElementsKind(map->elements_kind()));
  }

  {  // --- fast and slow aliased arguments map
    Handle<Map> map = isolate_->sloppy_arguments_map();
    map = Map::Copy(isolate_, map, "FastAliasedArguments");
    map->set_elements_kind(FAST_SLOPPY_ARGUMENTS_ELEMENTS);
    DCHECK_EQ(2, map->GetInObjectProperties());
    native_context()->set_fast_aliased_arguments_map(*map);

    map = Map::Copy(isolate_, map, "SlowAliasedArguments");
    map->set_elements_kind(SLOW_SLOPPY_ARGUMENTS_ELEMENTS);
    DCHECK_EQ(2, map->GetInObjectProperties());
    native_context()->set_slow_aliased_arguments_map(*map);
  }

  {  // --- strict mode arguments map
    const PropertyAttributes attributes =
        static_cast<PropertyAttributes>(DONT_ENUM | DONT_DELETE | READ_ONLY);

    // Create the ThrowTypeError function.
    Handle<AccessorPair> callee = factory->NewAccessorPair();

    DirectHandle<JSFunction> poison = GetThrowTypeErrorIntrinsic();

    // Install the ThrowTypeError function.
    callee->set_getter(*poison);
    callee->set_setter(*poison);

    // Create the map. Allocate one in-object field for length.
    DirectHandle<Map> map = factory->NewContextfulMapForCurrentContext(
        JS_ARGUMENTS_OBJECT_TYPE, JSStrictArgumentsObject::kSize,
        PACKED_ELEMENTS, 1);
    // Create the descriptor array for the arguments object.
    Map::EnsureDescriptorSlack(isolate_, map, 2);

    {  // length
      Descriptor d =
          Descriptor::DataField(isolate(), factory->length_string(),
                                JSStrictArgumentsObject::kLengthIndex,
                                DONT_ENUM, Representation::Tagged());
      map->AppendDescriptor(isolate(), &d);
    }
    {  // callee
      Descriptor d = Descriptor::AccessorConstant(factory->callee_string(),
                                                  callee, attributes);
      map->AppendDescriptor(isolate(), &d);
    }
    // @@iterator method is added later.

    DCHECK_EQ(native_context()->object_function()->prototype(),
              *isolate_->initial_object_prototype());
    Map::SetPrototype(isolate(), map, isolate_->initial_object_prototype());

    // Copy constructor from the sloppy arguments boilerplate.
    map->SetConstructor(
        native_context()->sloppy_arguments_map()->GetConstructor());

    native_context()->set_strict_arguments_map(*map);

    DCHECK(!map->is_dictionary_map());
    DCHECK(IsObjectElementsKind(map->elements_kind()));
  }

  {  // --- context extension
    // Create a function for the context extension objects.
    DirectHandle<JSFunction> context_extension_fun = CreateFunction(
        isolate_, factory->empty_string(), JS_CONTEXT_EXTENSION_OBJECT_TYPE,
        JSObject::kHeaderSize, 0, factory->the_hole_value(), Builtin::kIllegal,
        0, kDontAdapt);
    native_context()->set_context_extension_function(*context_extension_fun);
  }

  {
    // Set up the call-as-function delegate.
    DirectHandle<JSFunction> delegate = SimpleCreateFunction(
        isolate_, factory->empty_string(),
        Builtin::kHandleApiCallAsFunctionDelegate, 0, kDontAdapt);
    native_context()->set_call_as_function_delegate(*delegate);
  }

  {
    // Set up the call-as-constructor delegate.
    DirectHandle<JSFunction> delegate = SimpleCreateFunction(
        isolate_, factory->empty_string(),
        Builtin::kHandleApiCallAsConstructorDelegate, 0, kDontAdapt);
    native_context()->set_call_as_constructor_delegate(*delegate);
  }
}

Handle<JSFunction> Genesis::InstallTypedArray(const char* name,
                                              ElementsKind elements_kind,
                                              InstanceType constructor_type,
                                              int rab_gsab_initial_map_index) {
  Handle<JSObject> global =
      Handle<JSObject>(native_context()->global_object(), isolate());

  Handle<JSObject> typed_array_prototype = isolate()->typed_array_prototype();
  Handle<JSFunction> typed_array_function = isolate()->typed_array_function();

  Handle<JSFunction> result = InstallFunction(
      isolate(), global, name, JS_TYPED_ARRAY_TYPE,
      JSTypedArray::kSizeWithEmbedderFields, 0, factory()->the_hole_value(),
      Builtin::kTypedArrayConstructor, 3, kDontAdapt);
  result->initial_map()->set_elements_kind(elements_kind);

  CHECK(JSObject::SetPrototype(isolate(), result, typed_array_function, false,
                               kDontThrow)
            .FromJust());

  DirectHandle<Smi> bytes_per_element(
      Smi::FromInt(1 << ElementsKindToShiftSize(elements_kind)), isolate());

  InstallConstant(isolate(), result, "BYTES_PER_ELEMENT", bytes_per_element);

  // TODO(v8:11256, ishell): given the granularity of typed array constructor
  // protectors, consider creating only one constructor instance type for all
  // typed array constructors.
  SetConstructorInstanceType(isolate_, result, constructor_type);

  // Setup prototype object.
  DCHECK(IsJSObject(result->prototype()));
  Handle<JSObject> prototype(Cast<JSObject>(result->prototype()), isolate());

  CHECK(JSObject::SetPrototype(isolate(), prototype, typed_array_prototype,
                               false, kDontThrow)
            .FromJust());

  CHECK_NE(prototype->map().ptr(),
           isolate_->initial_object_prototype()->map().ptr());
  prototype->map()->set_instance_type(JS_TYPED_ARRAY_PROTOTYPE_TYPE);

  InstallConstant(isolate(), prototype, "BYTES_PER_ELEMENT", bytes_per_element);

  // RAB / GSAB backed TypedArrays don't have separate constructors, but they
  // have their own maps. Create the corresponding map here.
  DirectHandle<Map> rab_gsab_initial_map =
      factory()->NewContextfulMapForCurrentContext(
          JS_TYPED_ARRAY_TYPE, JSTypedArray::kSizeWithEmbedderFields,
          GetCorrespondingRabGsabElementsKind(elements_kind), 0);
  rab_gsab_initial_map->SetConstructor(*result);

  native_context()->set(rab_gsab_initial_map_index, *rab_gsab_initial_map,
                        UPDATE_WRITE_BARRIER, kReleaseStore);
  Map::SetPrototype(isolate(), rab_gsab_initial_map, prototype);

  return result;
}

void Genesis::InitializeExperimentalGlobal() {
#define FEATURE_INITIALIZE_GLOBAL(id, descr) InitializeGlobal_##id();

  // Initialize features from more mature to less mature, because less mature
  // features may depend on more mature features having been initialized
  // already.
  HARMONY_SHIPPING(FEATURE_INITIALIZE_GLOBAL)
  JAVASCRIPT_SHIPPING_FEATURES(FEATURE_INITIALIZE_GLOBAL)
  HARMONY_STAGED(FEATURE_INITIALIZE_GLOBAL)
  JAVASCRIPT_STAGED_FEATURES(FEATURE_INITIALIZE_GLOBAL)
  HARMONY_INPROGRESS(FEATURE_INITIALIZE_GLOBAL)
  JAVASCRIPT_INPROGRESS_FEATURES(FEATURE_INITIALIZE_GLOBAL)
#undef FEATURE_INITIALIZE_GLOBAL
  InitializeGlobal_regexp_linear_flag();
  InitializeGlobal_sharedarraybuffer();
}

namespace {
class TryCallScope {
 public:
  explicit TryCallScope(Isolate* isolate) : top(isolate->thread_local_top()) {
    top->IncrementCallDepth<true>(this);
  }
  ~TryCallScope() { top->DecrementCallDepth(this); }

 private:
  friend class i::ThreadLocalTop;
  ThreadLocalTop* top;
  Address previous_stack_height_;
};
}  // namespace

bool Genesis::CompileExtension(Isolate* isolate, v8::Extension* extension) {
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);
  DirectHandle<SharedFunctionInfo> function_info;

  Handle<String> source =
      isolate->factory()
          ->NewExternalStringFromOneByte(extension->source())
          .ToHandleChecked();
  DCHECK(source->IsOneByteRepresentation());

  // If we can't find the function in the cache, we compile a new
  // function and insert it into the cache.
  base::Vector<const char> name = base::CStrVector(extension->name());
  SourceCodeCache* cache = isolate->bootstrapper()->extensions_cache();
  Handle<Context> context(isolate->context(), isolate);
  DCHECK(IsNativeContext(*context));

  if (!cache->Lookup(isolate, name, &function_info)) {
    Handle<String> script_name =
        factory->NewStringFromUtf8(name).ToHandleChecked();
    ScriptCompiler::CompilationDetails compilation_details;
    MaybeDirectHandle<SharedFunctionInfo> maybe_function_info =
        Compiler::GetSharedFunctionInfoForScriptWithExtension(
            isolate, source, ScriptDetails(script_name), extension,
            ScriptCompiler::kNoCompileOptions, EXTENSION_CODE,
            &compilation_details);
    if (!maybe_function_info.ToHandle(&function_info)) return false;
    cache->Add(isolate, name, function_info);
  }

  // Set up the function context. Conceptually, we should clone the
  // function before overwriting the context but since we're in a
  // single-threaded environment it is not strictly necessary.
  Handle<JSFunction> fun =
      Factory::JSFunctionBuilder{isolate, function_info, context}.Build();

  // Call function using either the runtime object or the global
  // object as the receiver. Provide no parameters.
  Handle<Object> receiver = isolate->global_object();
  Handle<FixedArray> host_defined_options =
      isolate->factory()->empty_fixed_array();
  TryCallScope try_call_scope(isolate);
  // Blink generally assumes that context creation (where extension compilation
  // is part) cannot be interrupted.
  PostponeInterruptsScope postpone(isolate);
  return !Execution::TryCallScript(isolate, fun, receiver, host_defined_options)
              .is_null();
}

void Genesis::InitializeIteratorFunctions() {
  Isolate* isolate = isolate_;
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);
  DirectHandle<NativeContext> native_context = isolate->native_context();
  Handle<JSObject> iterator_prototype(
      native_context->initial_iterator_prototype(), isolate);

  {  // -- G e n e r a t o r
    PrototypeIterator iter(isolate, native_context->generator_function_map());
    Handle<JSObject> generator_function_prototype(iter.GetCurrent<JSObject>(),
                                                  isolate);
    Handle<JSFunction> generator_function_function = CreateFunction(
        isolate, "GeneratorFunction", JS_FUNCTION_TYPE,
        JSFunction::kSizeWithPrototype, 0, generator_function_prototype,
        Builtin::kGeneratorFunctionConstructor, 1, kDontAdapt);
    generator_function_function->set_prototype_or_initial_map(
        native_context->generator_function_map(), kReleaseStore);
    InstallWithIntrinsicDefaultProto(
        isolate, generator_function_function,
        Context::GENERATOR_FUNCTION_FUNCTION_INDEX);

    JSObject::ForceSetPrototype(isolate, generator_function_function,
                                isolate->function_function());
    JSObject::AddProperty(
        isolate, generator_function_prototype, factory->constructor_string(),
        generator_function_function,
        static_cast<PropertyAttributes>(DONT_ENUM | READ_ONLY));

    native_context->generator_function_map()->SetConstructor(
        *generator_function_function);
    native_context->generator_function_with_name_map()->SetConstructor(
        *generator_function_function);
  }

  {  // -- A s y n c G e n e r a t o r
    PrototypeIterator iter(isolate,
                           native_context->async_generator_function_map());
    Handle<JSObject> async_generator_function_prototype(
        iter.GetCurrent<JSObject>(), isolate);

    Handle<JSFunction> async_generator_function_function = CreateFunction(
        isolate, "AsyncGeneratorFunction", JS_FUNCTION_TYPE,
        JSFunction::kSizeWithPrototype, 0, async_generator_function_prototype,
        Builtin::kAsyncGeneratorFunctionConstructor, 1, kDontAdapt);
    async_generator_function_function->set_prototype_or_initial_map(
        native_context->async_generator_function_map(), kReleaseStore);
    InstallWithIntrinsicDefaultProto(
        isolate, async_generator_function_function,
        Context::ASYNC_GENERATOR_FUNCTION_FUNCTION_INDEX);

    JSObject::ForceSetPrototype(isolate, async_generator_function_function,
                                isolate->function_function());

    JSObject::AddProperty(
        isolate, async_generator_function_prototype,
        factory->constructor_string(), async_generator_function_function,
        static_cast<PropertyAttributes>(DONT_ENUM | READ_ONLY));

    native_context->async_generator_function_map()->SetConstructor(
        *async_generator_function_function);
    native_context->async_generator_function_with_name_map()->SetConstructor(
        *async_generator_function_function);
  }

  {  // -- S e t I t e r a t o r
    // Setup %SetIteratorPrototype%.
    Handle<JSObject> prototype =
        factory->NewJSObject(isolate->object_function(), AllocationType::kOld);
    JSObject::ForceSetPrototype(isolate, prototype, iterator_prototype);

    InstallToStringTag(isolate, prototype, factory->SetIterator_string());

    // Install the next function on the {prototype}.
    InstallFunctionWithBuiltinId(isolate, prototype, "next",
                                 Builtin::kSetIteratorPrototypeNext, 0, kAdapt);
    native_context->set_initial_set_iterator_prototype(*prototype);
    CHECK_NE(prototype->map().ptr(),
             isolate_->initial_object_prototype()->map().ptr());
    prototype->map()->set_instance_type(JS_SET_ITERATOR_PROTOTYPE_TYPE);

    // Setup SetIterator constructor.
    DirectHandle<JSFunction> set_iterator_function =
        CreateFunction(isolate, "SetIterator", JS_SET_VALUE_ITERATOR_TYPE,
                       JSSetIterator::kHeaderSize, 0, prototype,
                       Builtin::kIllegal, 0, kDontAdapt);
    set_iterator_function->shared()->set_native(false);

    Handle<Map> set_value_iterator_map(set_iterator_function->initial_map(),
                                       isolate);
    native_context->set_set_value_iterator_map(*set_value_iterator_map);

    DirectHandle<Map> set_key_value_iterator_map = Map::Copy(
        isolate, set_value_iterator_map, "JS_SET_KEY_VALUE_ITERATOR_TYPE");
    set_key_value_iterator_map->set_instance_type(
        JS_SET_KEY_VALUE_ITERATOR_TYPE);
    native_context->set_set_key_value_iterator_map(*set_key_value_iterator_map);
  }

  {  // -- M a p I t e r a t o r
    // Setup %MapIteratorPrototype%.
    Handle<JSObject> prototype =
        factory->NewJSObject(isolate->object_function(), AllocationType::kOld);
    JSObject::ForceSetPrototype(isolate, prototype, iterator_prototype);

    InstallToStringTag(isolate, prototype, factory->MapIterator_string());

    // Install the next function on the {prototype}.
    InstallFunctionWithBuiltinId(isolate, prototype, "next",
                                 Builtin::kMapIteratorPrototypeNext, 0, kAdapt);
    native_context->set_initial_map_iterator_prototype(*prototype);
    CHECK_NE(prototype->map().ptr(),
             isolate_->initial_object_prototype()->map().ptr());
    prototype->map()->set_instance_type(JS_MAP_ITERATOR_PROTOTYPE_TYPE);

    // Setup MapIterator constructor.
    DirectHandle<JSFunction> map_iterator_function =
        CreateFunction(isolate, "MapIterator", JS_MAP_KEY_ITERATOR_TYPE,
                       JSMapIterator::kHeaderSize, 0, prototype,
                       Builtin::kIllegal, 0, kDontAdapt);
    map_iterator_function->shared()->set_native(false);

    Handle<Map> map_key_iterator_map(map_iterator_function->initial_map(),
                                     isolate);
    native_context->set_map_key_iterator_map(*map_key_iterator_map);

    DirectHandle<Map> map_key_value_iterator_map = Map::Copy(
        isolate, map_key_iterator_map, "JS_MAP_KEY_VALUE_ITERATOR_TYPE");
    map_key_value_iterator_map->set_instance_type(
        JS_MAP_KEY_VALUE_ITERATOR_TYPE);
    native_context->set_map_key_value_iterator_map(*map_key_value_iterator_map);

    DirectHandle<Map> map_value_iterator_map =
        Map::Copy(isolate, map_key_iterator_map, "JS_MAP_VALUE_ITERATOR_TYPE");
    map_value_iterator_map->set_instance_type(JS_MAP_VALUE_ITERATOR_TYPE);
    native_context->set_map_value_iterator_map(*map_value_iterator_map);
  }

  {  // -- A s y n c F u n c t i o n
    // Builtin functions for AsyncFunction.
    PrototypeIterator iter(isolate, native_context->async_function_map());
    Handle<JSObject> async_function_prototype(iter.GetCurrent<JSObject>(),
                                              isolate);

    Handle<JSFunction> async_function_constructor = CreateFunction(
        isolate, "AsyncFunction", JS_FUNCTION_TYPE,
        JSFunction::kSizeWithPrototype, 0, async_function_prototype,
        Builtin::kAsyncFunctionConstructor, 1, kDontAdapt);
    async_function_constructor->set_prototype_or_initial_map(
        native_context->async_function_map(), kReleaseStore);
    InstallWithIntrinsicDefaultProto(isolate, async_function_constructor,
                                     Context::ASYNC_FUNCTION_FUNCTION_INDEX);

    native_context->set_async_function_constructor(*async_function_constructor);
    JSObject::ForceSetPrototype(isolate, async_function_constructor,
                                isolate->function_function());

    JSObject::AddProperty(
        isolate, async_function_prototype, factory->constructor_string(),
        async_function_constructor,
        static_cast<PropertyAttributes>(DONT_ENUM | READ_ONLY));

    // Async functions don't have a prototype, but they use generator objects
    // under the hood to model the suspend/resume (in await). Instead of using
    // the "prototype" / initial_map machinery (like for (async) generators),
    // there's one global (per native context) map here that is used for the
    // async function generator objects. These objects never escape to user
    // JavaScript anyways.
    DirectHandle<Map> async_function_object_map =
        factory->NewContextfulMapForCurrentContext(
            JS_ASYNC_FUNCTION_OBJECT_TYPE, JSAsyncFunctionObject::kHeaderSize);
    native_context->set_async_function_object_map(*async_function_object_map);

    isolate_->async_function_map()->SetConstructor(*async_function_constructor);
    isolate_->async_function_with_name_map()->SetConstructor(
        *async_function_constructor);
  }
}

void Genesis::InitializeCallSiteBuiltins() {
  Factory* factory = isolate()->factory();
  HandleScope scope(isolate());
  // -- C a l l S i t e
  // Builtin functions for CallSite.

  // CallSites are a special case; the constructor is for our private use
  // only, therefore we set it up as a builtin that throws. Internally, we use
  // CallSiteUtils::Construct to create CallSite objects.

  DirectHandle<JSFunction> callsite_fun = CreateFunction(
      isolate(), "CallSite", JS_OBJECT_TYPE, JSObject::kHeaderSize, 0,
      factory->the_hole_value(), Builtin::kUnsupportedThrower, 0, kDontAdapt);
  isolate()->native_context()->set_callsite_function(*callsite_fun);

  // Setup CallSite.prototype.
  Handle<JSObject> prototype(Cast<JSObject>(callsite_fun->instance_prototype()),
                             isolate());

  struct FunctionInfo {
    const char* name;
    Builtin id;
  };

  FunctionInfo infos[] = {
      {"getColumnNumber", Builtin::kCallSitePrototypeGetColumnNumber},
      {"getEnclosingColumnNumber",
       Builtin::kCallSitePrototypeGetEnclosingColumnNumber},
      {"getEnclosingLineNumber",
       Builtin::kCallSitePrototypeGetEnclosingLineNumber},
      {"getEvalOrigin", Builtin::kCallSitePrototypeGetEvalOrigin},
      {"getFileName", Builtin::kCallSitePrototypeGetFileName},
      {"getFunction", Builtin::kCallSitePrototypeGetFunction},
      {"getFunctionName", Builtin::kCallSitePrototypeGetFunctionName},
      {"getLineNumber", Builtin::kCallSitePrototypeGetLineNumber},
      {"getMethodName", Builtin::kCallSitePrototypeGetMethodName},
      {"getPosition", Builtin::kCallSitePrototypeGetPosition},
      {"getPromiseIndex", Builtin::kCallSitePrototypeGetPromiseIndex},
      {"getScriptNameOrSourceURL",
       Builtin::kCallSitePrototypeGetScriptNameOrSourceURL},
      {"getScriptHash", Builtin::kCallSitePrototypeGetScriptHash},
      {"getThis", Builtin::kCallSitePrototypeGetThis},
      {"getTypeName", Builtin::kCallSitePrototypeGetTypeName},
      {"isAsync", Builtin::kCallSitePrototypeIsAsync},
      {"isConstructor", Builtin::kCallSitePrototypeIsConstructor},
      {"isEval", Builtin::kCallSitePrototypeIsEval},
      {"isNative", Builtin::kCallSitePrototypeIsNative},
      {"isPromiseAll", Builtin::kCallSitePrototypeIsPromiseAll},
      {"isToplevel", Builtin::kCallSitePrototypeIsToplevel},
      {"toString", Builtin::kCallSitePrototypeToString}};

  PropertyAttributes attrs =
      static_cast<PropertyAttributes>(DONT_ENUM | DONT_DELETE | READ_ONLY);

  for (const FunctionInfo& info : infos) {
    SimpleInstallFunction(isolate(), prototype, info.name, info.id, 0, kAdapt,
                          attrs);
  }
}

void Genesis::InitializeConsole(Handle<JSObject> extras_binding) {
  HandleScope scope(isolate());
  Factory* factory = isolate_->factory();

  // -- C o n s o l e
  Handle<String> name = factory->console_string();

  Handle<NativeContext> context(isolate_->native_context());
  Handle<JSGlobalObject> global(context->global_object(), isolate());
  Handle<SharedFunctionInfo> info = factory->NewSharedFunctionInfoForBuiltin(
      name, Builtin::kIllegal, 0, kDontAdapt);
  info->set_language_mode(LanguageMode::kStrict);

  Handle<JSFunction> cons =
      Factory::JSFunctionBuilder{isolate(), info, context}.Build();
  Handle<JSObject> empty = factory->NewJSObject(isolate_->object_function());
  JSFunction::SetPrototype(cons, empty);

  Handle<JSObject> console = factory->NewJSObject(cons, AllocationType::kOld);
  DCHECK(IsJSObject(*console));

  JSObject::AddProperty(isolate_, extras_binding, name, console, DONT_ENUM);
  // TODO(v8:11989): remove this in the next release
  JSObject::AddProperty(isolate_, global, name, console, DONT_ENUM);

  SimpleInstallFunction(isolate_, console, "debug", Builtin::kConsoleDebug, 0,
                        kDontAdapt, NONE);
  SimpleInstallFunction(isolate_, console, "error", Builtin::kConsoleError, 0,
                        kDontAdapt, NONE);
  SimpleInstallFunction(isolate_, console, "info", Builtin::kConsoleInfo, 0,
                        kDontAdapt, NONE);
  SimpleInstallFunction(isolate_, console, "log", Builtin::kConsoleLog, 0,
                        kDontAdapt, NONE);
  SimpleInstallFunction(isolate_, console, "warn", Builtin::kConsoleWarn, 0,
                        kDontAdapt, NONE);
  SimpleInstallFunction(isolate_, console, "dir", Builtin::kConsoleDir, 0,
                        kDontAdapt, NONE);
  SimpleInstallFunction(isolate_, console, "dirxml", Builtin::kConsoleDirXml, 0,
                        kDontAdapt, NONE);
  SimpleInstallFunction(isolate_, console, "table", Builtin::kConsoleTable, 0,
                        kDontAdapt, NONE);
  SimpleInstallFunction(isolate_, console, "trace", Builtin::kConsoleTrace, 0,
                        kDontAdapt, NONE);
  SimpleInstallFunction(isolate_, console, "group", Builtin::kConsoleGroup, 0,
                        kDontAdapt, NONE);
  SimpleInstallFunction(isolate_, console, "groupCollapsed",
                        Builtin::kConsoleGroupCollapsed, 0, kDontAdapt, NONE);
  SimpleInstallFunction(isolate_, console, "groupEnd",
                        Builtin::kConsoleGroupEnd, 0, kDontAdapt, NONE);
  SimpleInstallFunction(isolate_, console, "clear", Builtin::kConsoleClear, 0,
                        kDontAdapt, NONE);
  SimpleInstallFunction(isolate_, console, "count", Builtin::kConsoleCount, 0,
                        kDontAdapt, NONE);
  SimpleInstallFunction(isolate_, console, "countReset",
                        Builtin::kConsoleCountReset, 0, kDontAdapt, NONE);
  SimpleInstallFunction(isolate_, console, "assert",
                        Builtin::kFastConsoleAssert, 0, kDontAdapt, NONE);
  SimpleInstallFunction(isolate_, console, "profile", Builtin::kConsoleProfile,
                        0, kDontAdapt, NONE);
  SimpleInstallFunction(isolate_, console, "profileEnd",
                        Builtin::kConsoleProfileEnd, 0, kDontAdapt, NONE);
  SimpleInstallFunction(isolate_, console, "time", Builtin::kConsoleTime, 0,
                        kDontAdapt, NONE);
  SimpleInstallFunction(isolate_, console, "timeLog", Builtin::kConsoleTimeLog,
                        0, kDontAdapt, NONE);
  SimpleInstallFunction(isolate_, console, "timeEnd", Builtin::kConsoleTimeEnd,
                        0, kDontAdapt, NONE);
  SimpleInstallFunction(isolate_, console, "timeStamp",
                        Builtin::kConsoleTimeStamp, 0, kDontAdapt, NONE);
  SimpleInstallFunction(isolate_, console, "context", Builtin::kConsoleContext,
                        1, kDontAdapt, NONE);
  InstallToStringTag(isolate_, console, "console");
}

#define EMPTY_INITIALIZE_GLOBAL_FOR_FEATURE(id) \
  void Genesis::InitializeGlobal_##id() {}

EMPTY_INITIALIZE_GLOBAL_FOR_FEATURE(harmony_import_attributes)
EMPTY_INITIALIZE_GLOBAL_FOR_FEATURE(js_regexp_modifiers)
EMPTY_INITIALIZE_GLOBAL_FOR_FEATURE(js_regexp_duplicate_named_groups)
EMPTY_INITIALIZE_GLOBAL_FOR_FEATURE(js_decorators)

#ifdef V8_INTL_SUPPORT
EMPTY_INITIALIZE_GLOBAL_FOR_FEATURE(harmony_intl_best_fit_matcher)
EMPTY_INITIALIZE_GLOBAL_FOR_FEATURE(harmony_remove_intl_locale_info_getters)
#endif  // V8_INTL_SUPPORT

#undef EMPTY_INITIALIZE_GLOBAL_FOR_FEATURE

void Genesis::InitializeGlobal_harmony_iterator_helpers() {
  if (!v8_flags.harmony_iterator_helpers) return;

  // --- Iterator
  Handle<JSGlobalObject> global(native_context()->global_object(), isolate());
  Handle<JSObject> iterator_prototype(
      native_context()->initial_iterator_prototype(), isolate());
  Handle<JSFunction> iterator_function = InstallFunction(
      isolate(), global, "Iterator", JS_OBJECT_TYPE, JSObject::kHeaderSize, 0,
      iterator_prototype, Builtin::kIteratorConstructor, 0, kAdapt);
  SimpleInstallFunction(isolate(), iterator_function, "from",
                        Builtin::kIteratorFrom, 1, kAdapt);
  InstallWithIntrinsicDefaultProto(isolate(), iterator_function,
                                   Context::ITERATOR_FUNCTION_INDEX);

  // --- %WrapForValidIteratorPrototype%
  Handle<JSObject> wrap_for_valid_iterator_prototype = factory()->NewJSObject(
      isolate()->object_function(), AllocationType::kOld);
  JSObject::ForceSetPrototype(isolate(), wrap_for_valid_iterator_prototype,
                              iterator_prototype);
  JSObject::AddProperty(isolate(), iterator_prototype,
                        factory()->constructor_string(), iterator_function,
                        DONT_ENUM);
  SimpleInstallFunction(isolate(), wrap_for_valid_iterator_prototype, "next",
                        Builtin::kWrapForValidIteratorPrototypeNext, 0, kAdapt);
  SimpleInstallFunction(isolate(), wrap_for_valid_iterator_prototype, "return",
                        Builtin::kWrapForValidIteratorPrototypeReturn, 0,
                        kAdapt);
  DirectHandle<Map> valid_iterator_wrapper_map =
      factory()->NewContextfulMapForCurrentContext(
          JS_VALID_ITERATOR_WRAPPER_TYPE, JSValidIteratorWrapper::kHeaderSize,
          TERMINAL_FAST_ELEMENTS_KIND, 0);
  Map::SetPrototype(isolate(), valid_iterator_wrapper_map,
```