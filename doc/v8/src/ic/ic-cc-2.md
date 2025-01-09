Response:
My thinking process to arrive at the summary goes like this:

1. **Understand the Request:** The core request is to analyze a specific section of `v8/src/ic/ic.cc` and describe its functionality, relate it to JavaScript, explain any logic, point out potential errors, and finally summarize its purpose. The prompt emphasizes that this is part 3 of a 6-part analysis, suggesting we focus on the specific code snippet provided.

2. **Initial Code Scan and Keyword Spotting:** I quickly scanned the code for recurring patterns and keywords:
    * `StoreIC`, `KeyedStoreIC`: This immediately tells me the code is related to storing properties, both named and indexed.
    * `LookupIterator`:  Indicates a process of finding properties, including going up the prototype chain.
    * `Handle`, `MaybeHandle`: These are V8's smart pointers, so I know I'm looking at object manipulation within the engine.
    * `JSObject`, `JSGlobalObject`, `JSProxy`, `Map`: These are V8's internal object representations.
    * `TypeError`, `ReferenceError`:  These signal potential error conditions.
    * `UpdateCaches`, `ComputeHandler`, `StoreElementHandler`: These look like core functions for managing the IC's caching mechanism.
    * `state()`, `NO_FEEDBACK`, `MONOMORPHIC`, `POLYMORPHIC`, `GENERIC`: These terms relate to the state of the inline cache.
    * `v8_flags.use_ic`: This points to feature flags controlling IC usage.
    * `DefineOwnDataProperty`, `Object::SetProperty`, `JSReceiver::CreateDataProperty`: These are different ways of setting properties, with varying levels of strictness.
    * `transition_map`, `interceptor`, `accessor`, `data`, `field`: These are different types of property lookups and handlers.
    * `StoreHandler`: This seems to be a class responsible for generating the actual code (handlers) for storing properties.
    * `KeyedAccessStoreMode`:  This appears to relate to how array elements are stored.

3. **Segmenting the Code:** I mentally divided the code into logical blocks:
    * The `StoreGlobalIC::Store` function, which handles stores to global variables.
    * The `DefineOwnDataProperty` helper function.
    * The main `StoreIC::Store` function for general property stores.
    * The `StoreIC::UpdateCaches` function, dealing with updating the inline cache.
    * The `StoreIC::ComputeHandler` function, responsible for determining the appropriate store handler based on the lookup result.
    * The `KeyedStoreIC::UpdateStoreElement` function, focusing on updates to array elements.
    * The `KeyedStoreIC::StoreElementHandler` function, generating handlers for array element stores.
    * The `KeyedStoreIC::StoreElementPolymorphicHandlers` function, which seems to manage polymorphic handlers for array element stores.

4. **Analyzing Each Block:** For each block, I tried to understand its purpose and how it interacts with other blocks. I focused on:
    * **Inputs and Outputs:** What kind of data does the function take, and what does it return?
    * **Core Logic:** What are the main steps the function performs?  Are there conditional branches based on object types or IC state?
    * **Error Handling:** Are there checks for invalid operations or attempts to access uninitialized variables?
    * **Caching Mechanisms:** How does the code update or utilize the inline cache to optimize future operations?
    * ** връзка с JavaScript:** How does this code relate to common JavaScript operations?

5. **Connecting to JavaScript:**  I thought about which JavaScript operations would trigger these parts of the V8 engine. For example:
    * Assigning to a global variable (`globalThis.x = 5`).
    * Assigning to a regular object property (`obj.y = 10`).
    * Assigning to an array element (`arr[0] = 20`).
    * Defining a new property on an object (`obj.z = 30`).
    * Interactions with Proxies.
    * The difference between assigning to a `const` variable and a `let` variable.

6. **Identifying Potential Errors:** I looked for patterns that could lead to runtime errors in JavaScript:
    * Assigning to a `const` variable.
    * Accessing a `let` variable before it's initialized.
    * Trying to set properties on `null` or `undefined`.
    * Violations of Proxy traps.
    * Issues related to accessors (getters and setters).

7. **Inferring Assumptions and Outputs:** Where the code had explicit checks or branches, I tried to imagine example inputs and what the expected behavior (output) would be. For instance, if an object is a `JSProxy`, certain optimizations are skipped.

8. **Synthesizing the Summary:**  Finally, I combined my understanding of each block into a concise summary, highlighting the main responsibilities of the code and its role in the overall V8 pipeline. I focused on the concepts of storing properties, handling different object types, using inline caching for optimization, and dealing with various error conditions. I made sure the summary addressed the "part 3" requirement by focusing on the provided code.

9. **Refinement and Organization:**  I organized the information into the requested sections (Functionality, JavaScript Relation, Logic, Errors, Summary) and used clear and concise language. I used the keywords identified in the initial scan to ensure the explanation was accurate within the V8 context. I specifically noted the IC states and their implications.

This iterative process of scanning, segmenting, analyzing, connecting, and synthesizing allowed me to break down the complex C++ code into understandable components and extract the relevant information for the summary.
好的，让我们来分析一下这段 V8 源代码片段，并尝试归纳其功能。

**功能列举:**

这段代码主要负责 V8 引擎中**存储（Store）属性**的功能，特别是针对以下几种情况：

1. **存储全局变量 (StoreGlobalIC):**
   -  查找脚本上下文中的变量。
   -  处理 `const` 变量的赋值错误（抛出 `TypeError`）。
   -  处理未初始化 `let` 或 `const` 变量的访问（抛出 `ReferenceError`）。
   -  使用内联缓存 (IC) 优化全局变量的存储。
   -  区分可变和不可变的脚本上下文变量。

2. **定义自有数据属性 (DefineOwnDataProperty):**
   -  用于在对象自身上定义新的数据属性。
   -  处理 `JSProxy` 的特殊情况，需要调用 Proxy 的 `DefineOwnProperty` 陷阱。
   -  处理 WebAssembly 对象的特殊情况，不允许定义属性。
   -  处理对象从字典模式到快速模式的转换。
   -  检查访问权限。

3. **通用属性存储 (StoreIC::Store):**
   -  处理普通对象的属性存储。
   -  处理原型链上的属性存储。
   -  处理 `null` 和 `undefined` 值的属性存储（抛出 `TypeError`）。
   -  处理私有字段和符号的存储。
   -  使用内联缓存 (IC) 优化属性存储。
   -  区分定义自有属性 (`IsAnyDefineOwn`) 和修改现有属性。

4. **更新内联缓存 (StoreIC::UpdateCaches):**
   -  在成功存储属性后，更新 IC 以加速后续相同属性的访问。
   -  根据属性查找的结果，选择合适的 Handler。
   -  处理全局变量的特殊情况。

5. **计算 Handler (StoreIC::ComputeHandler):**
   -  根据属性查找的不同状态 (例如：Transition, Interceptor, Accessor, Data) 计算出合适的存储 Handler。
   -  Handler 包含了优化的代码或指向慢速路径的指针。
   -  处理各种复杂的属性场景，例如：访问器属性、拦截器、原生数据属性、API setter 等。
   -  处理 `JSProxy` 的存储。

6. **键值存储 (KeyedStoreIC):**
   -  专门处理数组元素的存储。
   -  处理不同类型的数组 (例如：Packed, Holey, TypedArray)。
   -  根据数组的状态和类型更新 IC。
   -  处理数组扩容和越界访问的情况。
   -  支持多态内联缓存，处理多种数组类型。

**JavaScript 功能关系和举例:**

这段代码直接关系到 JavaScript 中对对象属性进行赋值的操作。

**1. 存储全局变量:**

```javascript
// 对应 StoreGlobalIC::Store

// 声明并赋值全局变量
var globalVar = 10;

// 重新赋值全局变量
globalVar = 20;

// 尝试赋值给常量（会抛出 TypeError）
const constVar = 30;
// constVar = 40; // TypeError: Assignment to constant variable.

// 访问未初始化的 let 变量 (会抛出 ReferenceError)
// console.log(uninitializedLet); // ReferenceError: Cannot access 'uninitializedLet' before initialization
let uninitializedLet;
uninitializedLet = 50;
```

**2. 定义自有数据属性:**

```javascript
// 对应 DefineOwnDataProperty

const obj = {};
// 定义新属性
obj.newProperty = 100;

// 对于 Proxy
const proxy = new Proxy({}, {
  defineProperty(target, prop, descriptor) {
    console.log(`Defining property ${prop}`);
    return Reflect.defineProperty(target, prop, descriptor);
  }
});
proxy.proxyProperty = 200; // 会触发 Proxy 的 defineProperty 陷阱
```

**3. 通用属性存储:**

```javascript
// 对应 StoreIC::Store

const myObject = { existingProperty: 1 };
myObject.existingProperty = 2; // 修改现有属性
myObject.newProperty = 3;      // 定义新属性

const protoObject = { protoProp: 4 };
const childObject = Object.create(protoObject);
childObject.childProp = 5;
childObject.protoProp = 6; // 修改原型链上的属性 (会在 childObject 上创建同名属性)

// 尝试给 null 或 undefined 赋值 (会抛出 TypeError)
// null.prop = 7; // TypeError: Cannot set properties of null
// undefined.prop = 8; // TypeError: Cannot set properties of undefined
```

**4. 键值存储:**

```javascript
// 对应 KeyedStoreIC

const myArray = [10, 20, 30];
myArray[0] = 11; // 修改数组元素
myArray[3] = 40; // 添加新元素 (如果数组是可扩展的)

const fixedArray = Object.seal([1, 2, 3]);
// fixedArray[0] = 4; // 可以修改
// fixedArray[3] = 5; // TypeError: Cannot add property 3, object is not extensible

const typedArray = new Int32Array(3);
typedArray[0] = 100;
```

**代码逻辑推理（假设输入与输出）:**

**假设输入:**

- `StoreGlobalIC::Store`: 尝试给一个已声明为 `const` 的全局变量 `myConst` 赋值。
  - `name`:  表示变量名的字符串 "myConst"。
  - `value`:  要赋的值。
  - `lookup_result.mode`:  `kConst` (表示常量)。

**预期输出:**

- `TypeError`，错误消息类似 "Assignment to constant variable."。

**假设输入:**

- `StoreIC::Store`: 尝试给一个普通对象 `myObj` 的属性 `myProp` 赋值。
  - `object`:  表示 `myObj` 的 `Handle`。
  - `name`:  表示属性名的字符串 "myProp"。
  - `value`:  要赋的值。
  - 假设 `myObj` 是一个普通的快速模式对象，没有拦截器或访问器。

**预期输出:**

- 如果 `myProp` 已经存在，则更新 `myObj` 的 `myProp` 属性值为 `value`。
- 如果 `myProp` 不存在，则在 `myObj` 上添加新的属性 `myProp` 并赋值为 `value`。
- 返回 `value`。

**用户常见的编程错误:**

1. **给常量赋值:**  尝试修改使用 `const` 声明的变量的值。
   ```javascript
   const PI = 3.14159;
   // PI = 3.14; // TypeError: Assignment to constant variable.
   ```

2. **在 `null` 或 `undefined` 上设置属性:**  这是非常常见的错误，会导致运行时错误。
   ```javascript
   let myVar = null;
   // myVar.someProperty = 10; // TypeError: Cannot set properties of null

   let anotherVar; // undefined
   // anotherVar.anotherProperty = 20; // TypeError: Cannot set properties of undefined
   ```

3. **在不可扩展的对象上添加属性:**  当使用 `Object.freeze` 或 `Object.seal` 或 `Object.preventExtensions` 后，尝试添加新属性会失败。
   ```javascript
   const frozenObj = Object.freeze({});
   // frozenObj.newProp = 10; // TypeError: Cannot add property newProp, object is not extensible

   const sealedObj = Object.seal({});
   // sealedObj.anotherProp = 20; // TypeError: Cannot add property anotherProp, object is not extensible
   ```

4. **访问未初始化的 `let` 或 `const` 变量:**  在声明但未赋值之前访问 `let` 或 `const` 变量会导致 `ReferenceError`。
   ```javascript
   // console.log(myLet); // ReferenceError: Cannot access 'myLet' before initialization
   let myLet = 5;

   // console.log(myConst); // ReferenceError: Cannot access 'myConst' before initialization
   const myConst = 10;
   ```

**功能归纳 (针对第 3 部分):**

作为六部分分析的第三部分，这段代码主要聚焦于 V8 引擎中**属性存储 (Store) 的核心机制**。它涵盖了从最简单的全局变量赋值到复杂的对象属性操作，并深入探讨了 V8 如何利用内联缓存 (IC) 来优化这些操作。

**具体来说，第 3 部分主要负责处理以下关键方面：**

- **不同类型的属性存储:**  区分全局变量、普通对象属性和数组元素的存储。
- **属性查找和处理:**  利用 `LookupIterator` 来定位属性，并根据属性的类型和状态采取不同的存储策略。
- **内联缓存 (IC):**  详细展示了如何更新和利用 IC 来加速后续的属性访问，包括不同状态 (Monomorphic, Polymorphic, Generic) 的处理。
- **错误处理:**  负责在存储过程中检测并抛出常见的 JavaScript 错误，例如给常量赋值或在 `null`/`undefined` 上设置属性。
- **Handler 的选择:**  根据属性查找的结果，动态选择合适的 Handler 来执行存储操作，这体现了 V8 的优化策略。

总而言之，这部分代码是 V8 引擎实现高效属性赋值的核心组成部分，它直接影响了 JavaScript 代码的性能和正确性。

Prompt: 
```
这是目录为v8/src/ic/ic.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/ic/ic.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共6部分，请归纳一下它的功能

"""
// Look up in script context table.
  Handle<String> str_name = Cast<String>(name);
  Handle<JSGlobalObject> global = isolate()->global_object();
  DirectHandle<ScriptContextTable> script_contexts(
      global->native_context()->script_context_table(), isolate());

  VariableLookupResult lookup_result;
  if (script_contexts->Lookup(str_name, &lookup_result)) {
    DisallowGarbageCollection no_gc;
    DisableGCMole no_gcmole;
    Tagged<Context> script_context =
        script_contexts->get(lookup_result.context_index);
    if (IsImmutableLexicalVariableMode(lookup_result.mode)) {
      AllowGarbageCollection yes_gc;
      return TypeError(MessageTemplate::kConstAssign, global, name);
    }

    Tagged<Object> previous_value =
        script_context->get(lookup_result.slot_index);

    if (IsTheHole(previous_value, isolate())) {
      // Do not install stubs and stay pre-monomorphic for uninitialized
      // accesses.
      AllowGarbageCollection yes_gc;
      THROW_NEW_ERROR(
          isolate(),
          NewReferenceError(MessageTemplate::kAccessedUninitializedVariable,
                            name));
    }

    bool use_ic = (state() != NO_FEEDBACK) && v8_flags.use_ic;
    if (use_ic) {
      if (nexus()->ConfigureLexicalVarMode(
              lookup_result.context_index, lookup_result.slot_index,
              IsImmutableLexicalVariableMode(lookup_result.mode))) {
        TRACE_HANDLER_STATS(isolate(), StoreGlobalIC_StoreScriptContextField);
      } else {
        // Given combination of indices can't be encoded, so use slow stub.
        TRACE_HANDLER_STATS(isolate(), StoreGlobalIC_SlowStub);
        SetCache(name, StoreHandler::StoreSlow(isolate()));
      }
      TraceIC("StoreGlobalIC", name);
    } else if (state() == NO_FEEDBACK) {
      TraceIC("StoreGlobalIC", name);
    }
    if (v8_flags.script_context_mutable_heap_number ||
        v8_flags.const_tracking_let) {
      AllowGarbageCollection yes_gc;
      Context::StoreScriptContextAndUpdateSlotProperty(
          handle(script_context, isolate()), lookup_result.slot_index, value,
          isolate());
    } else {
      script_context->set(lookup_result.slot_index, *value);
    }
    return value;
  }

  return StoreIC::Store(global, name, value);
}

namespace {
Maybe<bool> DefineOwnDataProperty(LookupIterator* it,
                                  LookupIterator::State original_state,
                                  Handle<JSAny> value,
                                  Maybe<ShouldThrow> should_throw,
                                  StoreOrigin store_origin) {
  // It should not be possible to call DefineOwnDataProperty in a
  // contextual store (indicated by IsJSGlobalObject()).
  DCHECK(!IsJSGlobalObject(*it->GetReceiver(), it->isolate()));

  // Handle special cases that can't be handled by
  // DefineOwnPropertyIgnoreAttributes first.
  switch (it->state()) {
    case LookupIterator::JSPROXY: {
      PropertyDescriptor new_desc;
      new_desc.set_value(value);
      new_desc.set_writable(true);
      new_desc.set_enumerable(true);
      new_desc.set_configurable(true);
      DCHECK_EQ(original_state, LookupIterator::JSPROXY);
      // TODO(joyee): this will start the lookup again. Ideally we should
      // implement something that reuses the existing LookupIterator.
      return JSProxy::DefineOwnProperty(it->isolate(), it->GetHolder<JSProxy>(),
                                        it->GetName(), &new_desc, should_throw);
    }
    case LookupIterator::WASM_OBJECT:
      RETURN_FAILURE(it->isolate(), kThrowOnError,
                     NewTypeError(MessageTemplate::kWasmObjectsAreOpaque));
    // When lazy feedback is disabled, the original state could be different
    // while the object is already prepared for TRANSITION.
    case LookupIterator::TRANSITION: {
      switch (original_state) {
        case LookupIterator::JSPROXY:
        case LookupIterator::WASM_OBJECT:
        case LookupIterator::TRANSITION:
        case LookupIterator::DATA:
        case LookupIterator::INTERCEPTOR:
        case LookupIterator::ACCESSOR:
        case LookupIterator::TYPED_ARRAY_INDEX_NOT_FOUND:
          UNREACHABLE();
        case LookupIterator::ACCESS_CHECK: {
          DCHECK(!IsAccessCheckNeeded(*it->GetHolder<JSObject>()));
          [[fallthrough]];
        }
        case LookupIterator::NOT_FOUND:
          return Object::AddDataProperty(it, value, NONE,
                                         Nothing<ShouldThrow>(), store_origin,
                                         EnforceDefineSemantics::kDefine);
      }
    }
    case LookupIterator::ACCESS_CHECK:
    case LookupIterator::NOT_FOUND:
    case LookupIterator::DATA:
    case LookupIterator::ACCESSOR:
    case LookupIterator::INTERCEPTOR:
    case LookupIterator::TYPED_ARRAY_INDEX_NOT_FOUND:
      break;
  }

  // We need to restart to handle interceptors properly.
  it->Restart();

  return JSObject::DefineOwnPropertyIgnoreAttributes(
      it, value, NONE, should_throw, JSObject::DONT_FORCE_FIELD,
      EnforceDefineSemantics::kDefine, store_origin);
}
}  // namespace

MaybeHandle<Object> StoreIC::Store(Handle<JSAny> object, Handle<Name> name,
                                   Handle<Object> value,
                                   StoreOrigin store_origin) {
  // TODO(verwaest): Let SetProperty do the migration, since storing a property
  // might deprecate the current map again, if value does not fit.
  if (MigrateDeprecated(isolate(), object)) {
    // KeyedStoreIC should handle DefineKeyedOwnIC with deprecated maps directly
    // instead of reusing this method.
    DCHECK(!IsDefineKeyedOwnIC());
    DCHECK(!name->IsPrivateName());

    PropertyKey key(isolate(), name);
    if (IsDefineNamedOwnIC()) {
      MAYBE_RETURN_NULL(JSReceiver::CreateDataProperty(
          isolate(), object, key, value, Nothing<ShouldThrow>()));
    } else {
      LookupIterator it(isolate(), object, key, LookupIterator::DEFAULT);
      MAYBE_RETURN_NULL(Object::SetProperty(&it, value, StoreOrigin::kNamed));
    }
    return value;
  }

  bool use_ic = (state() != NO_FEEDBACK) && v8_flags.use_ic;
  // If the object is undefined or null it's illegal to try to set any
  // properties on it; throw a TypeError in that case.
  if (IsNullOrUndefined(*object, isolate())) {
    if (use_ic) {
      // Ensure the IC state progresses.
      TRACE_HANDLER_STATS(isolate(), StoreIC_NonReceiver);
      update_lookup_start_object_map(object);
      SetCache(name, StoreHandler::StoreSlow(isolate()));
      TraceIC("StoreIC", name);
    }
    return TypeError(MessageTemplate::kNonObjectPropertyStoreWithProperty, name,
                     object);
  }

  JSObject::MakePrototypesFast(object, kStartAtPrototype, isolate());
  PropertyKey key(isolate(), name);
  LookupIterator it(
      isolate(), object, key,
      IsAnyDefineOwn() ? LookupIterator::OWN : LookupIterator::DEFAULT);

  if (name->IsPrivate()) {
    if (name->IsPrivateName()) {
      DCHECK(!IsDefineNamedOwnIC());
      Maybe<bool> can_store =
          JSReceiver::CheckPrivateNameStore(&it, IsDefineKeyedOwnIC());
      MAYBE_RETURN_NULL(can_store);
      if (!can_store.FromJust()) {
        return isolate()->factory()->undefined_value();
      }
    }

    // IC handling of private fields/symbols stores on JSProxy is not
    // supported.
    if (IsJSProxy(*object)) {
      use_ic = false;
    }
  }

  // For IsAnyDefineOwn(), we can't simply do CreateDataProperty below
  // because we need to check the attributes before UpdateCaches updates
  // the state of the LookupIterator.
  LookupIterator::State original_state = it.state();
  // We'll defer the check for JSProxy and objects with named interceptors,
  // because the defineProperty traps need to be called first if they are
  // present. We can also skip this for private names since they are not
  // bound by configurability or extensibility checks, and errors would've
  // been thrown if the private field already exists in the object.
  if (IsAnyDefineOwn() && !name->IsPrivateName() && IsJSObject(*object) &&
      !Cast<JSObject>(object)->HasNamedInterceptor()) {
    Maybe<bool> can_define = JSObject::CheckIfCanDefineAsConfigurable(
        isolate(), &it, value, Nothing<ShouldThrow>());
    MAYBE_RETURN_NULL(can_define);
    if (!can_define.FromJust()) {
      return isolate()->factory()->undefined_value();
    }
    // Restart the lookup iterator updated by CheckIfCanDefineAsConfigurable()
    // for UpdateCaches() to handle access checks.
    if (use_ic && IsAccessCheckNeeded(*object)) {
      it.Restart();
    }
  }

  if (use_ic) {
    UpdateCaches(&it, value, store_origin);
  } else if (state() == NO_FEEDBACK) {
    // Tracing IC Stats for No Feedback State.
    IsStoreGlobalIC() ? TraceIC("StoreGlobalIC", name)
                      : TraceIC("StoreIC", name);
  }

  // TODO(v8:12548): refactor DefinedNamedOwnIC and SetNamedIC as subclasses
  // of StoreIC so their logic doesn't get mixed here.
  // ES #sec-definefield
  // ES #sec-runtime-semantics-propertydefinitionevaluation
  // IsAnyDefineOwn() can be true when this method is reused by KeyedStoreIC.
  if (IsAnyDefineOwn()) {
    if (name->IsPrivateName()) {
      // We should define private fields without triggering traps or checking
      // extensibility.
      MAYBE_RETURN_NULL(
          JSReceiver::AddPrivateField(&it, value, Nothing<ShouldThrow>()));
    } else {
      MAYBE_RETURN_NULL(
          DefineOwnDataProperty(&it, original_state, Cast<JSAny>(value),
                                Nothing<ShouldThrow>(), store_origin));
    }
  } else {
    MAYBE_RETURN_NULL(Object::SetProperty(&it, value, store_origin));
  }
  return value;
}

void StoreIC::UpdateCaches(LookupIterator* lookup, DirectHandle<Object> value,
                           StoreOrigin store_origin) {
  MaybeObjectHandle handler;
  if (LookupForWrite(lookup, value, store_origin)) {
    if (IsStoreGlobalIC()) {
      if (lookup->state() == LookupIterator::DATA &&
          lookup->GetReceiver().is_identical_to(lookup->GetHolder<Object>())) {
        DCHECK(IsJSGlobalObject(*lookup->GetReceiver()));
        // Now update the cell in the feedback vector.
        nexus()->ConfigurePropertyCellMode(lookup->GetPropertyCell());
        TraceIC("StoreGlobalIC", lookup->GetName());
        return;
      }
    }
    handler = ComputeHandler(lookup);
  } else {
    set_slow_stub_reason("LookupForWrite said 'false'");
    handler = MaybeObjectHandle(StoreHandler::StoreSlow(isolate()));
  }
  // Can't use {lookup->name()} because the LookupIterator might be in
  // "elements" mode for keys that are strings representing integers above
  // JSArray::kMaxIndex.
  SetCache(lookup->GetName(), handler);
  TraceIC("StoreIC", lookup->GetName());
}

MaybeObjectHandle StoreIC::ComputeHandler(LookupIterator* lookup) {
  switch (lookup->state()) {
    case LookupIterator::TRANSITION: {
      Handle<JSObject> store_target = lookup->GetStoreTarget<JSObject>();
      if (IsJSGlobalObject(*store_target)) {
        TRACE_HANDLER_STATS(isolate(), StoreIC_StoreGlobalTransitionDH);

        if (IsJSGlobalObject(*lookup_start_object_map())) {
          DCHECK(IsStoreGlobalIC());
#ifdef DEBUG
          DirectHandle<JSObject> holder = lookup->GetHolder<JSObject>();
          DCHECK_EQ(*lookup->GetReceiver(), *holder);
          DCHECK_EQ(*store_target, *holder);
#endif
          return StoreHandler::StoreGlobal(lookup->transition_cell());
        }
        if (IsDefineKeyedOwnIC()) {
          // Private field can't be deleted from this global object and can't
          // be overwritten, so install slow handler in order to make store IC
          // throw if a private name already exists.
          TRACE_HANDLER_STATS(isolate(), StoreIC_SlowStub);
          return MaybeObjectHandle(StoreHandler::StoreSlow(isolate()));
        }

        DirectHandle<Smi> smi_handler =
            StoreHandler::StoreGlobalProxy(isolate());
        Handle<Object> handler = StoreHandler::StoreThroughPrototype(
            isolate(), lookup_start_object_map(), store_target, *smi_handler,
            MaybeObjectHandle::Weak(lookup->transition_cell()));
        return MaybeObjectHandle(handler);
      }
      // Dictionary-to-fast transitions are not expected and not supported.
      DCHECK_IMPLIES(!lookup->transition_map()->is_dictionary_map(),
                     !lookup_start_object_map()->is_dictionary_map());

      DCHECK(lookup->IsCacheableTransition());
      if (IsAnyDefineOwn()) {
        return StoreHandler::StoreOwnTransition(isolate(),
                                                lookup->transition_map());
      }
      return StoreHandler::StoreTransition(isolate(), lookup->transition_map());
    }

    case LookupIterator::INTERCEPTOR: {
      Handle<JSObject> holder = lookup->GetHolder<JSObject>();
      Tagged<InterceptorInfo> info = holder->GetNamedInterceptor();

      // If the interceptor is on the receiver...
      if (lookup->HolderIsReceiverOrHiddenPrototype() && !info->non_masking()) {
        // ...return a store interceptor Smi handler if there is a setter
        // interceptor and it's not DefineNamedOwnIC or DefineKeyedOwnIC
        // (which should call the definer)...
        if (!IsUndefined(info->setter(), isolate()) && !IsAnyDefineOwn()) {
          return MaybeObjectHandle(StoreHandler::StoreInterceptor(isolate()));
        }
        // ...otherwise return a slow-case Smi handler, which invokes the
        // definer for DefineNamedOwnIC.
        return MaybeObjectHandle(StoreHandler::StoreSlow(isolate()));
      }

      // If the interceptor is a getter/query interceptor on the prototype
      // chain, return an invalidatable slow handler so it can turn fast if the
      // interceptor is masked by a regular property later.
      DCHECK(!IsUndefined(info->getter(), isolate()) ||
             !IsUndefined(info->query(), isolate()));
      Handle<Object> handler = StoreHandler::StoreThroughPrototype(
          isolate(), lookup_start_object_map(), holder,
          *StoreHandler::StoreSlow(isolate()));
      return MaybeObjectHandle(handler);
    }

    case LookupIterator::ACCESSOR: {
      // This is currently guaranteed by checks in StoreIC::Store.
      Handle<JSObject> receiver = Cast<JSObject>(lookup->GetReceiver());
      Handle<JSObject> holder = lookup->GetHolder<JSObject>();
      DCHECK(!IsAccessCheckNeeded(*receiver) || lookup->name()->IsPrivate());

      if (IsAnyDefineOwn()) {
        set_slow_stub_reason("define own with existing accessor");
        TRACE_HANDLER_STATS(isolate(), StoreIC_SlowStub);
        return MaybeObjectHandle(StoreHandler::StoreSlow(isolate()));
      }
      if (!holder->HasFastProperties()) {
        set_slow_stub_reason("accessor on slow map");
        TRACE_HANDLER_STATS(isolate(), StoreIC_SlowStub);
        MaybeObjectHandle handler =
            MaybeObjectHandle(StoreHandler::StoreSlow(isolate()));
        return handler;
      }
      Handle<Object> accessors = lookup->GetAccessors();
      if (IsAccessorInfo(*accessors)) {
        DirectHandle<AccessorInfo> info = Cast<AccessorInfo>(accessors);
        if (!info->has_setter(isolate())) {
          set_slow_stub_reason("setter == kNullAddress");
          TRACE_HANDLER_STATS(isolate(), StoreIC_SlowStub);
          return MaybeObjectHandle(StoreHandler::StoreSlow(isolate()));
        }
        if (!lookup->HolderIsReceiverOrHiddenPrototype()) {
          set_slow_stub_reason("native data property in prototype chain");
          TRACE_HANDLER_STATS(isolate(), StoreIC_SlowStub);
          return MaybeObjectHandle(StoreHandler::StoreSlow(isolate()));
        }

        Handle<Smi> smi_handler = StoreHandler::StoreNativeDataProperty(
            isolate(), lookup->GetAccessorIndex());
        TRACE_HANDLER_STATS(isolate(), StoreIC_StoreNativeDataPropertyDH);
        if (receiver.is_identical_to(holder)) {
          return MaybeObjectHandle(smi_handler);
        }
        TRACE_HANDLER_STATS(isolate(),
                            StoreIC_StoreNativeDataPropertyOnPrototypeDH);
        return MaybeObjectHandle(StoreHandler::StoreThroughPrototype(
            isolate(), lookup_start_object_map(), holder, *smi_handler));

      } else if (IsAccessorPair(*accessors)) {
        Handle<AccessorPair> accessor_pair = Cast<AccessorPair>(accessors);
        Handle<Object> setter(accessor_pair->setter(), isolate());
        if (!IsCallableJSFunction(*setter) &&
            !IsFunctionTemplateInfo(*setter)) {
          set_slow_stub_reason("setter not a function");
          TRACE_HANDLER_STATS(isolate(), StoreIC_SlowStub);
          return MaybeObjectHandle(StoreHandler::StoreSlow(isolate()));
        }

        if ((IsFunctionTemplateInfo(*setter) &&
             Cast<FunctionTemplateInfo>(*setter)->BreakAtEntry(isolate())) ||
            (IsJSFunction(*setter) &&
             Cast<JSFunction>(*setter)->shared()->BreakAtEntry(isolate()))) {
          // Do not install an IC if the api function has a breakpoint.
          TRACE_HANDLER_STATS(isolate(), StoreIC_SlowStub);
          return MaybeObjectHandle(StoreHandler::StoreSlow(isolate()));
        }

        CallOptimization call_optimization(isolate(), setter);
        if (call_optimization.is_simple_api_call()) {
          CallOptimization::HolderLookup holder_lookup;
          Handle<JSObject> api_holder =
              call_optimization.LookupHolderOfExpectedType(
                  isolate(), lookup_start_object_map(), &holder_lookup);
          if (call_optimization.IsCompatibleReceiverMap(api_holder, holder,
                                                        holder_lookup)) {
            DirectHandle<Smi> smi_handler = StoreHandler::StoreApiSetter(
                isolate(),
                holder_lookup == CallOptimization::kHolderIsReceiver);

            Handle<NativeContext> accessor_context =
                GetAccessorContext(call_optimization, holder->map(), isolate());

            TRACE_HANDLER_STATS(isolate(), StoreIC_StoreApiSetterOnPrototypeDH);
            return MaybeObjectHandle(StoreHandler::StoreThroughPrototype(
                isolate(), lookup_start_object_map(), holder, *smi_handler,
                MaybeObjectHandle::Weak(call_optimization.api_call_info()),
                MaybeObjectHandle::Weak(accessor_context)));
          }
          set_slow_stub_reason("incompatible receiver");
          TRACE_HANDLER_STATS(isolate(), StoreIC_SlowStub);
          return MaybeObjectHandle(StoreHandler::StoreSlow(isolate()));
        } else if (IsFunctionTemplateInfo(*setter)) {
          set_slow_stub_reason("setter non-simple template");
          TRACE_HANDLER_STATS(isolate(), StoreIC_SlowStub);
          return MaybeObjectHandle(StoreHandler::StoreSlow(isolate()));
        }

        DCHECK(IsCallableJSFunction(*setter));
        if (receiver.is_identical_to(holder)) {
          TRACE_HANDLER_STATS(isolate(), StoreIC_StoreAccessorDH);
          return MaybeObjectHandle::Weak(accessor_pair);
        }
        TRACE_HANDLER_STATS(isolate(), StoreIC_StoreAccessorOnPrototypeDH);

        return MaybeObjectHandle(StoreHandler::StoreThroughPrototype(
            isolate(), lookup_start_object_map(), holder,
            *StoreHandler::StoreAccessorFromPrototype(isolate()),
            MaybeObjectHandle::Weak(setter)));
      }
      TRACE_HANDLER_STATS(isolate(), StoreIC_SlowStub);
      return MaybeObjectHandle(StoreHandler::StoreSlow(isolate()));
    }

    case LookupIterator::DATA: {
      // This is currently guaranteed by checks in StoreIC::Store.
      Handle<JSObject> receiver = Cast<JSObject>(lookup->GetReceiver());
      USE(receiver);
      Handle<JSObject> holder = lookup->GetHolder<JSObject>();
      DCHECK(!IsAccessCheckNeeded(*receiver) || lookup->name()->IsPrivate());

      DCHECK_EQ(PropertyKind::kData, lookup->property_details().kind());
      if (lookup->is_dictionary_holder()) {
        if (IsJSGlobalObject(*holder)) {
          TRACE_HANDLER_STATS(isolate(), StoreIC_StoreGlobalDH);
          return MaybeObjectHandle(
              StoreHandler::StoreGlobal(lookup->GetPropertyCell()));
        }
        TRACE_HANDLER_STATS(isolate(), StoreIC_StoreNormalDH);
        DCHECK(holder.is_identical_to(receiver));
        DCHECK_IMPLIES(!V8_DICT_PROPERTY_CONST_TRACKING_BOOL,
                       lookup->constness() == PropertyConstness::kMutable);

        Handle<Smi> handler = StoreHandler::StoreNormal(isolate());
        return MaybeObjectHandle(handler);
      }

      // -------------- Elements (for TypedArrays) -------------
      if (lookup->IsElement(*holder)) {
        TRACE_HANDLER_STATS(isolate(), StoreIC_SlowStub);
        return MaybeObjectHandle(StoreHandler::StoreSlow(isolate()));
      }

      // -------------- Fields --------------
      if (lookup->property_details().location() == PropertyLocation::kField) {
        TRACE_HANDLER_STATS(isolate(), StoreIC_StoreFieldDH);
        int descriptor = lookup->GetFieldDescriptorIndex();
        FieldIndex index = lookup->GetFieldIndex();
        if (V8_UNLIKELY(IsJSSharedStruct(*holder))) {
          return MaybeObjectHandle(StoreHandler::StoreSharedStructField(
              isolate(), descriptor, index, lookup->representation()));
        }
        PropertyConstness constness = lookup->constness();
        if (constness == PropertyConstness::kConst &&
            IsDefineNamedOwnICKind(nexus()->kind())) {
          // DefineNamedOwnICs are used for initializing object literals
          // therefore we must store the value unconditionally even to
          // VariableMode::kConst fields.
          constness = PropertyConstness::kMutable;
        }
        return MaybeObjectHandle(StoreHandler::StoreField(
            isolate(), descriptor, index, constness, lookup->representation()));
      }

      // -------------- Constant properties --------------
      DCHECK_EQ(PropertyLocation::kDescriptor,
                lookup->property_details().location());
      set_slow_stub_reason("constant property");
      TRACE_HANDLER_STATS(isolate(), StoreIC_SlowStub);
      return MaybeObjectHandle(StoreHandler::StoreSlow(isolate()));
    }
    case LookupIterator::JSPROXY: {
      Handle<JSReceiver> receiver = Cast<JSReceiver>(lookup->GetReceiver());
      Handle<JSProxy> holder = lookup->GetHolder<JSProxy>();

      // IsDefineNamedOwnIC() is true when we are defining public fields on a
      // Proxy. IsDefineKeyedOwnIC() is true when we are defining computed
      // fields in a Proxy. In these cases use the slow stub to invoke the
      // define trap.
      if (IsDefineNamedOwnIC() || IsDefineKeyedOwnIC()) {
        TRACE_HANDLER_STATS(isolate(), StoreIC_SlowStub);
        return MaybeObjectHandle(StoreHandler::StoreSlow(isolate()));
      }

      return MaybeObjectHandle(StoreHandler::StoreProxy(
          isolate(), lookup_start_object_map(), holder, receiver));
    }

    case LookupIterator::TYPED_ARRAY_INDEX_NOT_FOUND:
    case LookupIterator::ACCESS_CHECK:
    case LookupIterator::NOT_FOUND:
    case LookupIterator::WASM_OBJECT:
      UNREACHABLE();
  }
  return MaybeObjectHandle();
}

void KeyedStoreIC::UpdateStoreElement(Handle<Map> receiver_map,
                                      KeyedAccessStoreMode store_mode,
                                      Handle<Map> new_receiver_map) {
  std::vector<MapAndHandler> target_maps_and_handlers;
  nexus()->ExtractMapsAndHandlers(
      &target_maps_and_handlers,
      [this](Handle<Map> map) { return Map::TryUpdate(isolate(), map); });
  if (target_maps_and_handlers.empty()) {
    DirectHandle<Map> monomorphic_map = receiver_map;
    // If we transitioned to a map that is a more general map than incoming
    // then use the new map.
    if (IsTransitionOfMonomorphicTarget(*receiver_map, *new_receiver_map)) {
      monomorphic_map = new_receiver_map;
    }
    Handle<Object> handler = StoreElementHandler(monomorphic_map, store_mode);
    return ConfigureVectorState(Handle<Name>(), monomorphic_map, handler);
  }

  for (const MapAndHandler& map_and_handler : target_maps_and_handlers) {
    Handle<Map> map = map_and_handler.first;
    if (!map.is_null() && map->instance_type() == JS_PRIMITIVE_WRAPPER_TYPE) {
      DCHECK(!IsStoreInArrayLiteralIC());
      set_slow_stub_reason("JSPrimitiveWrapper");
      return;
    }
  }

  // There are several special cases where an IC that is MONOMORPHIC can still
  // transition to a different IC that handles a superset of the original IC.
  // Handle those here if the receiver map hasn't changed or it has transitioned
  // to a more general kind.
  KeyedAccessStoreMode old_store_mode = GetKeyedAccessStoreMode();
  Handle<Map> previous_receiver_map = target_maps_and_handlers.at(0).first;
  if (state() == MONOMORPHIC) {
    DirectHandle<Map> transitioned_receiver_map = new_receiver_map;
    if (IsTransitionOfMonomorphicTarget(*previous_receiver_map,
                                        *transitioned_receiver_map)) {
      // If the "old" and "new" maps are in the same elements map family, or
      // if they at least come from the same origin for a transitioning store,
      // stay MONOMORPHIC and use the map for the most generic ElementsKind.
      Handle<Object> handler =
          StoreElementHandler(transitioned_receiver_map, store_mode);
      ConfigureVectorState(Handle<Name>(), transitioned_receiver_map, handler);
      return;
    }
    // If there is no transition and if we have seen the same map earlier and
    // there is only a change in the store_mode we can still stay monomorphic.
    if (receiver_map.is_identical_to(previous_receiver_map) &&
        new_receiver_map.is_identical_to(receiver_map) &&
        StoreModeIsInBounds(old_store_mode) &&
        !StoreModeIsInBounds(store_mode)) {
      if (IsJSArrayMap(*receiver_map) &&
          JSArray::MayHaveReadOnlyLength(*receiver_map)) {
        set_slow_stub_reason(
            "can't generalize store mode (potentially read-only length)");
        return;
      }
      // A "normal" IC that handles stores can switch to a version that can
      // grow at the end of the array, handle OOB accesses or copy COW arrays
      // and still stay MONOMORPHIC.
      Handle<Object> handler = StoreElementHandler(receiver_map, store_mode);
      return ConfigureVectorState(Handle<Name>(), receiver_map, handler);
    }
  }

  DCHECK(state() != GENERIC);

  bool map_added =
      AddOneReceiverMapIfMissing(&target_maps_and_handlers, receiver_map);

  if (IsTransitionOfMonomorphicTarget(*receiver_map, *new_receiver_map)) {
    map_added |=
        AddOneReceiverMapIfMissing(&target_maps_and_handlers, new_receiver_map);
  }

  if (!map_added) {
    // If the miss wasn't due to an unseen map, a polymorphic stub
    // won't help, use the megamorphic stub which can handle everything.
    set_slow_stub_reason("same map added twice");
    return;
  }

  // If the maximum number of receiver maps has been exceeded, use the
  // megamorphic version of the IC.
  if (static_cast<int>(target_maps_and_handlers.size()) >
      v8_flags.max_valid_polymorphic_map_count) {
    return;
  }

  // Make sure all polymorphic handlers have the same store mode, otherwise the
  // megamorphic stub must be used.
  if (!StoreModeIsInBounds(old_store_mode)) {
    if (StoreModeIsInBounds(store_mode)) {
      store_mode = old_store_mode;
    } else if (store_mode != old_store_mode) {
      set_slow_stub_reason("store mode mismatch");
      return;
    }
  }

  // If the store mode isn't the standard mode, make sure that all polymorphic
  // receivers are either external arrays, or all "normal" arrays with writable
  // length. Otherwise, use the megamorphic stub.
  if (!StoreModeIsInBounds(store_mode)) {
    size_t external_arrays = 0;
    for (MapAndHandler map_and_handler : target_maps_and_handlers) {
      DirectHandle<Map> map = map_and_handler.first;
      if (IsJSArrayMap(*map) && JSArray::MayHaveReadOnlyLength(*map)) {
        set_slow_stub_reason(
            "unsupported combination of arrays (potentially read-only length)");
        return;

      } else if (map->has_typed_array_or_rab_gsab_typed_array_elements()) {
        DCHECK(!IsStoreInArrayLiteralIC());
        external_arrays++;
      }
    }
    if (external_arrays != 0 &&
        external_arrays != target_maps_and_handlers.size()) {
      DCHECK(!IsStoreInArrayLiteralIC());
      set_slow_stub_reason(
          "unsupported combination of external and normal arrays");
      return;
    }
  }

  StoreElementPolymorphicHandlers(&target_maps_and_handlers, store_mode);
  if (target_maps_and_handlers.empty()) {
    Handle<Object> handler = StoreElementHandler(receiver_map, store_mode);
    ConfigureVectorState(Handle<Name>(), receiver_map, handler);
  } else if (target_maps_and_handlers.size() == 1) {
    ConfigureVectorState(Handle<Name>(), target_maps_and_handlers[0].first,
                         target_maps_and_handlers[0].second);
  } else {
    ConfigureVectorState(Handle<Name>(), target_maps_and_handlers);
  }
}

Handle<Object> KeyedStoreIC::StoreElementHandler(
    DirectHandle<Map> receiver_map, KeyedAccessStoreMode store_mode,
    MaybeHandle<UnionOf<Smi, Cell>> prev_validity_cell) {
  // The only case when could keep using non-slow element store handler for
  // a fast array with potentially read-only elements is when it's an
  // initializing store to array literal.
  DCHECK_IMPLIES(
      !receiver_map->has_dictionary_elements() &&
          receiver_map->ShouldCheckForReadOnlyElementsInPrototypeChain(
              isolate()),
      IsStoreInArrayLiteralIC());

  if (!IsJSObjectMap(*receiver_map)) {
    // DefineKeyedOwnIC, which is used to define computed fields in instances,
    // should handled by the slow stub below instead of the proxy stub.
    if (IsJSProxyMap(*receiver_map) && !IsDefineKeyedOwnIC()) {
      return StoreHandler::StoreProxy(isolate());
    }

    // Wasm objects or other kind of special objects go through the slow stub.
    TRACE_HANDLER_STATS(isolate(), KeyedStoreIC_SlowStub);
    return StoreHandler::StoreSlow(isolate(), store_mode);
  }

  // TODO(ishell): move to StoreHandler::StoreElement().
  Handle<Code> code;
  if (receiver_map->has_sloppy_arguments_elements()) {
    // TODO(jgruber): Update counter name.
    TRACE_HANDLER_STATS(isolate(), KeyedStoreIC_KeyedStoreSloppyArgumentsStub);
    code = StoreHandler::StoreSloppyArgumentsBuiltin(isolate(), store_mode);
  } else if (receiver_map->has_fast_elements() ||
             receiver_map->has_sealed_elements() ||
             receiver_map->has_nonextensible_elements() ||
             receiver_map->has_typed_array_or_rab_gsab_typed_array_elements()) {
    // TODO(jgruber): Update counter name.
    TRACE_HANDLER_STATS(isolate(), KeyedStoreIC_StoreFastElementStub);
    if (IsJSArgumentsObjectMap(*receiver_map) &&
        receiver_map->has_fast_packed_elements()) {
      // Allow fast behaviour for in-bounds stores while making it miss and
      // properly handle the out of bounds store case.
      code = StoreHandler::StoreFastElementBuiltin(
          isolate(), KeyedAccessStoreMode::kInBounds);
    } else {
      code = StoreHandler::StoreFastElementBuiltin(isolate(), store_mode);
      if (receiver_map->has_typed_array_or_rab_gsab_typed_array_elements()) {
        return code;
      }
    }
  } else if (IsStoreInArrayLiteralIC()) {
    // TODO(jgruber): Update counter name.
    TRACE_HANDLER_STATS(isolate(), StoreInArrayLiteralIC_SlowStub);
    return StoreHandler::StoreSlow(isolate(), store_mode);
  } else {
    // TODO(jgruber): Update counter name.
    TRACE_HANDLER_STATS(isolate(), KeyedStoreIC_StoreElementStub);
    DCHECK(DICTIONARY_ELEMENTS == receiver_map->elements_kind() ||
           receiver_map->has_frozen_elements());
    return StoreHandler::StoreSlow(isolate(), store_mode);
  }

  if (IsAnyDefineOwn() || IsStoreInArrayLiteralIC()) return code;
  Handle<UnionOf<Smi, Cell>> validity_cell;
  if (!prev_validity_cell.ToHandle(&validity_cell)) {
    validity_cell =
        Map::GetOrCreatePrototypeChainValidityCell(receiver_map, isolate());
  }
  if (IsSmi(*validity_cell)) {
    // There's no prototype validity cell to check, so we can just use the stub.
    return code;
  }
  Handle<StoreHandler> handler = isolate()->factory()->NewStoreHandler(0);
  handler->set_validity_cell(*validity_cell);
  handler->set_smi_handler(*code);
  return handler;
}

void KeyedStoreIC::StoreElementPolymorphicHandlers(
    std::vector<MapAndHandler>* receiver_maps_and_handlers,
    KeyedAccessStoreMode store_mode) {
  std::vector<Handle<Map>> receiver_maps;
  receiver_maps.reserve(receiver_maps_and_handlers->size());
  f
"""


```