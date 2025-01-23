Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/runtime/runtime-object.cc`.

Here's a breakdown of the thought process to achieve the desired summary:

1. **Identify the core purpose of the file:** The file is `runtime-object.cc` located within the `v8/src/runtime` directory. This strongly suggests it contains implementations for runtime functions related to object manipulation in V8. Runtime functions are low-level operations called from generated JavaScript code or other internal V8 components.

2. **Analyze individual `RUNTIME_FUNCTION` definitions:** The code is structured as a series of `RUNTIME_FUNCTION` definitions. Each of these functions represents a specific operation. The function names are descriptive and provide clues about their purpose. I'll process each function individually and then group them thematically.

3. **Categorize the functions:** As I analyze each function, I'll look for common themes to group them. Initial categories emerge quickly:
    * **Object Creation/Modification:** Functions like `Runtime_NewObject`, `Runtime_DefineAccessorPropertyUnchecked`, `Runtime_SetFunctionName`, `Runtime_DefineKeyedOwnPropertyInLiteral`, `Runtime_SetDataProperties`, `Runtime_CopyDataProperties`, etc. fall under this.
    * **Property Access/Manipulation:** Functions like `Runtime_GetFunctionName`, `Runtime_GetOwnPropertyDescriptorObject`, `Runtime_GetPrivateMember`, `Runtime_SetPrivateMember`.
    * **Type Checking:**  Functions like `Runtime_HasFastPackedElements`, `Runtime_IsJSReceiver`.
    * **Type Conversion:** Functions like `Runtime_ToObject`, `Runtime_ToNumber`, `Runtime_ToString`, etc.
    * **Prototype Chain Operations:** `Runtime_HasInPrototypeChain`.
    * **Iterator Related:** `Runtime_CreateIterResultObject`.
    * **Internal Data Structures (Swiss Table):** Functions related to `Runtime_SwissTableAllocate`, `Runtime_SwissTableAdd`, etc. These appear to be a temporary implementation.
    * **Slack Tracking:** `Runtime_CompleteInobjectSlackTrackingForMap`.
    * **Object Migration:** `Runtime_TryMigrateInstance`.
    * **Accessor Pairs:** `Runtime_CreatePrivateAccessors`, `Runtime_LoadPrivateGetter`, `Runtime_LoadPrivateSetter`.

4. **Explain the functionality of each function with examples (if related to Javascript):** For functions that directly correspond to JavaScript concepts, provide a simple JavaScript example to illustrate their usage or the underlying mechanism. For instance, `Runtime_NewObject` is related to `new Object()` or `{}`. `Runtime_DefineAccessorPropertyUnchecked` relates to `Object.defineProperty()` with a getter/setter. `Runtime_ToString` relates to implicit or explicit `toString()` calls.

5. **Address Torque (.tq) source:** The prompt specifically asks about `.tq` files. I need to check if any of the listed functions would *typically* have a `.tq` counterpart. While the provided code is `.cc`, the explanation should acknowledge the possibility of `.tq` implementations for performance-critical runtime functions.

6. **Handle Code Logic/Assumptions:**  For functions with internal logic (like `Runtime_DefineKeyedOwnPropertyInLiteral` with its feedback vector handling), describe the assumptions and potential inputs/outputs.

7. **Identify potential user errors:**  Point out common JavaScript errors that relate to the functionality of the runtime functions. For example, accessing properties on `null` or `undefined` is relevant to functions that handle object access. Trying to define non-configurable properties relates to property definition functions.

8. **Synthesize a high-level summary:**  After analyzing individual functions, provide a concise overall summary of the file's purpose.

9. **Structure the output:** Organize the information clearly with headings and bullet points for readability. Address all the points raised in the user's prompt.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:** Focus solely on the C++ code.
* **Correction:** Remember the prompt asks about the *relationship* to JavaScript. Actively look for these connections.
* **Initial thought:** Describe each function in extreme detail based on the C++ implementation.
* **Correction:**  Focus on the *functional* purpose from a higher level, explaining what the function *does* rather than *how* it does it internally (unless the "how" is essential to understanding the function's purpose, like the feedback vector in `Runtime_DefineKeyedOwnPropertyInLiteral`).
* **Initial thought:** Treat all `RUNTIME_FUNCTION` equally.
* **Correction:**  Prioritize explaining functions with clear JavaScript equivalents or those that represent core object operations. Acknowledge the existence of less obvious internal functions (like the Swiss Table ones) but don't dwell on their implementation details unless requested.
* **Remember the "Part 2" instruction:**  The user explicitly mentioned this is part 2. The summary should be a concluding overview, building upon any information potentially provided in "Part 1" (although we don't have that context here, a general concluding tone is appropriate).

By following these steps and iterating through the analysis, a comprehensive and informative summary can be generated.
这是对 `v8/src/runtime/runtime-object.cc` 源代码的功能归纳总结。

**功能归纳:**

`v8/src/runtime/runtime-object.cc` 文件包含了 V8 引擎中用于实现与 JavaScript 对象操作相关的运行时 (runtime) 函数。这些函数是 V8 引擎内部使用的低级操作，通常由编译器生成的代码或解释器直接调用，用于执行诸如对象创建、属性定义、类型转换等核心的 JavaScript 对象语义。

**具体功能细分:**

这个文件中的运行时函数主要涵盖以下几个方面：

* **对象创建和初始化:**
    * `Runtime_NewObject`: 创建一个新的 JavaScript 对象。
    * `Runtime_CompleteInobjectSlackTrackingForMap`:  完成 Map 对象的内联空闲空间跟踪。
* **属性定义和修改:**
    * `Runtime_DefineAccessorPropertyUnchecked`: 定义或修改对象的访问器属性（getter 和 setter），跳过某些检查。
    * `Runtime_SetFunctionName`: 设置函数对象的 `name` 属性。
    * `Runtime_DefineKeyedOwnPropertyInLiteral`: 在对象字面量中定义键值对属性，并可能更新内联缓存状态以优化后续访问。
    * `Runtime_SetDataProperties`: 将源对象的可枚举数据属性复制到目标对象。
    * `Runtime_CopyDataProperties`: 将源对象的所有自身数据属性复制到目标对象。
    * `Runtime_CopyDataPropertiesWithExcludedPropertiesOnStack`:  类似 `Runtime_CopyDataProperties`，但可以排除栈上的特定属性。
    * `Runtime_DefineSetterPropertyUnchecked`: 定义对象的 setter 属性。
    * `Runtime_DefineGetterPropertyUnchecked`: 定义对象的 getter 属性。
    * `Runtime_CreateDataProperty`:  创建一个新的数据属性。
    * `Runtime_SetOwnPropertyIgnoreAttributes`: 设置对象自身的属性，忽略属性的特性（如可写、可枚举、可配置）。
* **属性访问:**
    * `Runtime_GetFunctionName`: 获取函数对象的 `name` 属性。
    * `Runtime_GetOwnPropertyDescriptorObject`: 获取对象自身属性的描述符。
    * `Runtime_GetPrivateMember`: 获取对象的私有成员 (字段、方法或访问器)。
    * `Runtime_SetPrivateMember`: 设置对象的私有成员 (字段或访问器)。
    * `Runtime_LoadPrivateSetter`: 加载私有 setter 访问器。
    * `Runtime_LoadPrivateGetter`: 加载私有 getter 访问器。
    * `Runtime_CreatePrivateAccessors`: 创建私有访问器对 (getter 和 setter)。
* **类型检查:**
    * `Runtime_HasFastPackedElements`: 检查对象是否具有快速打包元素。
    * `Runtime_IsJSReceiver`: 检查一个值是否是 JS 接收器（对象或函数）。
* **类型转换:**
    * `Runtime_ToObject`: 将值转换为对象。
    * `Runtime_ToNumber`: 将值转换为数字。
    * `Runtime_ToNumeric`: 将值转换为数字或 BigInt。
    * `Runtime_ToLength`: 将值转换为适合用作数组长度的整数。
    * `Runtime_ToString`: 将值转换为字符串。
    * `Runtime_ToName`: 将值转换为可以用作属性键的字符串或 Symbol。
* **原型链操作:**
    * `Runtime_HasInPrototypeChain`: 检查一个对象是否存在于另一个对象的原型链上。
* **迭代器:**
    * `Runtime_CreateIterResultObject`: 创建一个迭代器结果对象。
* **对象迁移:**
    * `Runtime_TryMigrateInstance`: 尝试迁移对象的实例到更优化的表示形式。
* **内部数据结构 (Swiss Table):**
    *  一系列 `Runtime_SwissTable...` 函数，用于操作 `SwissNameDictionary`，这是一种用于存储对象属性的内部哈希表实现。 这些函数可能属于临时实现或正在进行的工作。

**关于 .tq 结尾：**

如果 `v8/src/runtime/runtime-object.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码** 文件。 Torque 是一种 V8 内部使用的领域特定语言，用于定义运行时函数的实现。 Torque 代码会被编译成 C++ 代码。目前提供的代码是 `.cc` 文件，所以是用 C++ 编写的。

**与 JavaScript 的关系及示例:**

这些运行时函数直接支持 JavaScript 语言的各种对象操作。以下是一些 JavaScript 代码示例以及与之相关的运行时函数：

* **对象创建:**
    ```javascript
    const obj = {}; // 对应 Runtime_NewObject
    const obj2 = new Object(); // 对应 Runtime_NewObject
    ```

* **定义属性:**
    ```javascript
    const obj = {};
    Object.defineProperty(obj, 'a', { value: 1, enumerable: true }); // 可能涉及 Runtime_DefineKeyedOwnPropertyInLiteral 或其他属性定义运行时函数
    obj.b = 2; // 可能涉及 Runtime_DefineKeyedOwnPropertyInLiteral 或其他属性定义运行时函数
    ```

* **定义访问器属性:**
    ```javascript
    const obj = {};
    Object.defineProperty(obj, 'c', {
      get() { return this._c; },
      set(value) { this._c = value; }
    }); // 对应 Runtime_DefineAccessorPropertyUnchecked
    ```

* **获取属性:**
    ```javascript
    const obj = { name: 'test' };
    console.log(obj.name); //  可能会间接涉及到属性查找相关的运行时函数
    function fn() {}
    console.log(fn.name); // 对应 Runtime_GetFunctionName
    ```

* **类型转换:**
    ```javascript
    const num = 10;
    const str = num.toString(); // 对应 Runtime_ToString
    const obj = {};
    const objStr = String(obj); // 对应 Runtime_ToString 或 Runtime_ToObject 再调用 toString
    ```

* **原型链检查:**
    ```javascript
    const arr = [];
    console.log(arr instanceof Array); // 内部可能使用与原型链相关的机制，如 Runtime_HasInPrototypeChain
    ```

**代码逻辑推理及假设输入输出:**

以 `Runtime_DefineKeyedOwnPropertyInLiteral` 为例：

**假设输入:**

* `object`: 一个 JSReceiver 对象 (例如，正在创建的对象字面量)。
* `name`: 属性名 (可以是字符串或 Symbol)。
* `value`: 属性值。
* `flag`:  一个整数标志，指示是否设置函数名等。
* `maybe_vector`: 一个可选的 FeedbackVector 对象，用于存储内联缓存信息。
* `index`: 如果 `maybe_vector` 存在，则表示反馈向量中的索引。

**代码逻辑:**

1. 检查是否需要设置函数名（如果 `value` 是函数且标志指示）。
2. 如果提供了 `FeedbackVector`，则尝试更新与该属性相关的内联缓存状态，以优化后续的属性访问。
3. 使用 `JSObject::DefineOwnPropertyIgnoreAttributes` 定义属性。

**输出:**

* 返回 `value` 本身。

**用户常见的编程错误:**

* **尝试访问 `null` 或 `undefined` 的属性:** 这会导致运行时抛出 `TypeError`。相关的运行时函数会在尝试操作这些值时进行检查。
    ```javascript
    let obj = null;
    console.log(obj.name); // TypeError: Cannot read properties of null
    ```

* **尝试修改不可配置或不可写的属性:** `Object.defineProperty` 允许定义属性的特性。如果尝试修改一个不可配置或不可写的属性，根据情况可能会静默失败或抛出 `TypeError`。相关的运行时函数会处理这些情况。
    ```javascript
    const obj = {};
    Object.defineProperty(obj, 'a', { value: 1, configurable: false, writable: false });
    obj.a = 2; // 静默失败或在严格模式下抛出 TypeError
    Object.defineProperty(obj, 'a', { configurable: true }); // TypeError: Cannot redefine property
    ```

* **在预期对象的地方使用了原始值:**  很多对象操作的运行时函数都期望输入是 JSReceiver。如果传递了原始值，V8 会尝试将其转换为对象 (装箱)，但有时这可能导致意外的行为或错误。

* **误用私有字段或方法:**  尝试在声明它们的类之外访问私有字段或方法会导致错误。相关的 `Runtime_GetPrivateMember` 和 `Runtime_SetPrivateMember` 函数会执行必要的检查。

**总结:**

`v8/src/runtime/runtime-object.cc` 是 V8 引擎中负责实现核心 JavaScript 对象操作的关键组成部分。它包含了一系列底层的运行时函数，用于创建、修改、访问对象属性，进行类型转换，处理原型链关系以及支持私有类成员等功能。这些运行时函数是 JavaScript 语言语义在 V8 引擎内部的具体实现。

### 提示词
```
这是目录为v8/src/runtime/runtime-object.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/runtime/runtime-object.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
et));
  } else {
    RETURN_RESULT_OR_FAILURE(
        isolate, JSFunction::GetDerivedMap(isolate, target, new_target));
  }
}

RUNTIME_FUNCTION(Runtime_CompleteInobjectSlackTrackingForMap) {
  DisallowGarbageCollection no_gc;
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());

  DirectHandle<Map> initial_map = args.at<Map>(0);
  MapUpdater::CompleteInobjectSlackTracking(isolate, *initial_map);

  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_TryMigrateInstance) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  DirectHandle<JSObject> js_object = args.at<JSObject>(0);
  // It could have been a DCHECK but we call this function directly from tests.
  if (!js_object->map()->is_deprecated()) return Smi::zero();
  // This call must not cause lazy deopts, because it's called from deferred
  // code where we can't handle lazy deopts for lack of a suitable bailout
  // ID. So we just try migration and signal failure if necessary,
  // which will also trigger a deopt.
  if (!JSObject::TryMigrateInstance(isolate, js_object)) return Smi::zero();
  return *js_object;
}

static bool IsValidAccessor(Isolate* isolate, DirectHandle<Object> obj) {
  return IsNullOrUndefined(*obj, isolate) || IsCallable(*obj);
}

// Implements part of 8.12.9 DefineOwnProperty.
// There are 3 cases that lead here:
// Step 4b - define a new accessor property.
// Steps 9c & 12 - replace an existing data property with an accessor property.
// Step 12 - update an existing accessor property with an accessor or generic
//           descriptor.
RUNTIME_FUNCTION(Runtime_DefineAccessorPropertyUnchecked) {
  HandleScope scope(isolate);
  DCHECK_EQ(5, args.length());
  Handle<JSObject> obj = args.at<JSObject>(0);
  CHECK(!IsNull(*obj, isolate));
  Handle<Name> name = args.at<Name>(1);
  DirectHandle<Object> getter = args.at(2);
  CHECK(IsValidAccessor(isolate, getter));
  DirectHandle<Object> setter = args.at(3);
  CHECK(IsValidAccessor(isolate, setter));
  auto attrs = PropertyAttributesFromInt(args.smi_value_at(4));

  RETURN_FAILURE_ON_EXCEPTION(
      isolate, JSObject::DefineOwnAccessorIgnoreAttributes(obj, name, getter,
                                                           setter, attrs));
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_SetFunctionName) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());
  Handle<Object> value = args.at(0);
  Handle<Name> name = args.at<Name>(1);
  DCHECK(IsJSFunction(*value));
  auto function = Cast<JSFunction>(value);
  DCHECK(!function->shared()->HasSharedName());
  DirectHandle<Map> function_map(function->map(), isolate);
  if (!JSFunction::SetName(function, name,
                           isolate->factory()->empty_string())) {
    return ReadOnlyRoots(isolate).exception();
  }
  // Class constructors do not reserve in-object space for name field.
  DCHECK_IMPLIES(!IsClassConstructor(function->shared()->kind()),
                 *function_map == function->map());
  return *value;
}

RUNTIME_FUNCTION(Runtime_DefineKeyedOwnPropertyInLiteral) {
  HandleScope scope(isolate);
  DCHECK_EQ(6, args.length());
  Handle<JSReceiver> object = args.at<JSReceiver>(0);
  Handle<Object> name = args.at(1);
  Handle<Object> value = args.at(2);
  int flag = args.smi_value_at(3);
  Handle<HeapObject> maybe_vector = args.at<HeapObject>(4);

  if (!IsUndefined(*maybe_vector)) {
    int index = args.tagged_index_value_at(5);
    DCHECK(IsName(*name));
    DCHECK(IsFeedbackVector(*maybe_vector));
    Handle<FeedbackVector> vector = Cast<FeedbackVector>(maybe_vector);
    FeedbackNexus nexus(isolate, vector, FeedbackVector::ToSlot(index));
    if (nexus.ic_state() == InlineCacheState::UNINITIALIZED) {
      if (IsUniqueName(*name)) {
        nexus.ConfigureMonomorphic(Cast<Name>(name),
                                   handle(object->map(), isolate),
                                   MaybeObjectHandle());
      } else {
        nexus.ConfigureMegamorphic(IcCheckType::kProperty);
      }
    } else if (nexus.ic_state() == InlineCacheState::MONOMORPHIC) {
      if (nexus.GetFirstMap() != object->map() || nexus.GetName() != *name) {
        nexus.ConfigureMegamorphic(IcCheckType::kProperty);
      }
    }
  }

  DefineKeyedOwnPropertyInLiteralFlags flags(flag);

  if (flags & DefineKeyedOwnPropertyInLiteralFlag::kSetFunctionName) {
    DCHECK(IsName(*name));
    DCHECK(IsJSFunction(*value));
    auto function = Cast<JSFunction>(value);
    DCHECK(!function->shared()->HasSharedName());
    DirectHandle<Map> function_map(function->map(), isolate);
    if (!JSFunction::SetName(function, Cast<Name>(name),
                             isolate->factory()->empty_string())) {
      return ReadOnlyRoots(isolate).exception();
    }
    // Class constructors do not reserve in-object space for name field.
    DCHECK_IMPLIES(!IsClassConstructor(function->shared()->kind()),
                   *function_map == function->map());
  }

  PropertyKey key(isolate, name);
  LookupIterator it(isolate, object, key, object, LookupIterator::OWN);

  Maybe<bool> result = JSObject::DefineOwnPropertyIgnoreAttributes(
      &it, value, PropertyAttributes::NONE, Just(kDontThrow));
  // Cannot fail since this should only be called when
  // creating an object literal.
  RETURN_FAILURE_IF_EXCEPTION(isolate);
  DCHECK(result.IsJust());
  USE(result);

  // Return the value so that
  // BaselineCompiler::VisitDefineKeyedOwnPropertyInLiteral doesn't have to
  // save the accumulator.
  return *value;
}

RUNTIME_FUNCTION(Runtime_HasFastPackedElements) {
  SealHandleScope shs(isolate);
  DCHECK_EQ(1, args.length());
  auto obj = Cast<HeapObject>(args[0]);
  return isolate->heap()->ToBoolean(
      IsFastPackedElementsKind(obj->map()->elements_kind()));
}

RUNTIME_FUNCTION(Runtime_IsJSReceiver) {
  SealHandleScope shs(isolate);
  DCHECK_EQ(1, args.length());
  Tagged<Object> obj = args[0];
  return isolate->heap()->ToBoolean(IsJSReceiver(obj));
}

RUNTIME_FUNCTION(Runtime_GetFunctionName) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  DirectHandle<JSFunction> function = args.at<JSFunction>(0);
  return *JSFunction::GetName(isolate, function);
}

RUNTIME_FUNCTION(Runtime_DefineGetterPropertyUnchecked) {
  HandleScope scope(isolate);
  DCHECK_EQ(4, args.length());
  Handle<JSObject> object = args.at<JSObject>(0);
  Handle<Name> name = args.at<Name>(1);
  Handle<JSFunction> getter = args.at<JSFunction>(2);
  auto attrs = PropertyAttributesFromInt(args.smi_value_at(3));

  if (Cast<String>(getter->shared()->Name())->length() == 0) {
    DirectHandle<Map> getter_map(getter->map(), isolate);
    if (!JSFunction::SetName(getter, name, isolate->factory()->get_string())) {
      return ReadOnlyRoots(isolate).exception();
    }
    CHECK_EQ(*getter_map, getter->map());
  }

  RETURN_FAILURE_ON_EXCEPTION(
      isolate,
      JSObject::DefineOwnAccessorIgnoreAttributes(
          object, name, getter, isolate->factory()->null_value(), attrs));
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_SetDataProperties) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());
  Handle<JSReceiver> target = args.at<JSReceiver>(0);
  Handle<Object> source = args.at(1);

  // 2. If source is undefined or null, let keys be an empty List.
  if (IsUndefined(*source, isolate) || IsNull(*source, isolate)) {
    return ReadOnlyRoots(isolate).undefined_value();
  }

  MAYBE_RETURN(JSReceiver::SetOrCopyDataProperties(
                   isolate, target, source,
                   PropertiesEnumerationMode::kEnumerationOrder),
               ReadOnlyRoots(isolate).exception());
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_CopyDataProperties) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());
  Handle<JSObject> target = args.at<JSObject>(0);
  Handle<Object> source = args.at(1);

  // 2. If source is undefined or null, let keys be an empty List.
  if (IsUndefined(*source, isolate) || IsNull(*source, isolate)) {
    return ReadOnlyRoots(isolate).undefined_value();
  }

  MAYBE_RETURN(
      JSReceiver::SetOrCopyDataProperties(
          isolate, target, source,
          PropertiesEnumerationMode::kPropertyAdditionOrder, {}, false),
      ReadOnlyRoots(isolate).exception());
  return ReadOnlyRoots(isolate).undefined_value();
}

namespace {

// Check that the excluded properties are within the stack range of the top of
// the stack, and the start of the JS frame.
void CheckExcludedPropertiesAreOnCallerStack(Isolate* isolate, Address base,
                                             int count) {
#ifdef DEBUG
  StackFrameIterator it(isolate);

  // Don't need to check when there's no excluded properties.
  if (count == 0) return;

  DCHECK(!it.done());

  // Properties are pass in order on the stack, which means that their addresses
  // are in reverse order in memory (because stacks grow backwards). So, we
  // need to check if the _last_ property address is before the stack end...
  Address last_property = base - (count - 1) * kSystemPointerSize;
  DCHECK_GE(last_property, it.frame()->sp());

  // ... and for the first JS frame, make sure the _first_ property address is
  // after that stack frame's start.
  for (; !it.done(); it.Advance()) {
    if (it.frame()->is_javascript()) {
      DCHECK_LT(base, it.frame()->fp());
      return;
    }
  }

  // We should always find a JS frame.
  UNREACHABLE();
#endif
}

}  // namespace

RUNTIME_FUNCTION(Runtime_CopyDataPropertiesWithExcludedPropertiesOnStack) {
  HandleScope scope(isolate);
  DCHECK_EQ(3, args.length());
  Handle<Object> source = args.at(0);
  int excluded_property_count = args.smi_value_at(1);
  // The excluded_property_base is passed as a raw stack pointer. This is safe
  // because the stack pointer is aligned, so it looks like a Smi to the GC.
  Address* excluded_property_base = reinterpret_cast<Address*>(args[2].ptr());
  DCHECK(HAS_SMI_TAG(reinterpret_cast<intptr_t>(excluded_property_base)));
  // Also make sure that the given base pointer points to to on-stack values.
  CheckExcludedPropertiesAreOnCallerStack(
      isolate, reinterpret_cast<Address>(excluded_property_base),
      excluded_property_count);

  // If source is undefined or null, throw a non-coercible error.
  if (IsNullOrUndefined(*source, isolate)) {
    return ErrorUtils::ThrowLoadFromNullOrUndefined(isolate, source,
                                                    MaybeHandle<Object>());
  }

  DirectHandleVector<Object> excluded_properties(isolate,
                                                 excluded_property_count);
  for (int i = 0; i < excluded_property_count; i++) {
    // Because the excluded properties on stack is from high address
    // to low address, so we need to use sub
    Handle<Object> property(excluded_property_base - i);
    uint32_t property_num;
    // We convert string to number if possible, in cases of computed
    // properties resolving to numbers, which would've been strings
    // instead because of our call to %ToName() in the desugaring for
    // computed properties.
    if (IsString(*property) &&
        Cast<String>(*property)->AsArrayIndex(&property_num)) {
      property = isolate->factory()->NewNumberFromUint(property_num);
    }

    excluded_properties[i] = property;
  }

  Handle<JSObject> target =
      isolate->factory()->NewJSObject(isolate->object_function());
  MAYBE_RETURN(
      JSReceiver::SetOrCopyDataProperties(
          isolate, target, source,
          PropertiesEnumerationMode::kPropertyAdditionOrder,
          {excluded_properties.data(), excluded_properties.size()}, false),
      ReadOnlyRoots(isolate).exception());
  return *target;
}

RUNTIME_FUNCTION(Runtime_DefineSetterPropertyUnchecked) {
  HandleScope scope(isolate);
  DCHECK_EQ(4, args.length());
  Handle<JSObject> object = args.at<JSObject>(0);
  Handle<Name> name = args.at<Name>(1);
  Handle<JSFunction> setter = args.at<JSFunction>(2);
  auto attrs = PropertyAttributesFromInt(args.smi_value_at(3));

  if (Cast<String>(setter->shared()->Name())->length() == 0) {
    DirectHandle<Map> setter_map(setter->map(), isolate);
    if (!JSFunction::SetName(setter, name, isolate->factory()->set_string())) {
      return ReadOnlyRoots(isolate).exception();
    }
    CHECK_EQ(*setter_map, setter->map());
  }

  RETURN_FAILURE_ON_EXCEPTION(
      isolate,
      JSObject::DefineOwnAccessorIgnoreAttributes(
          object, name, isolate->factory()->null_value(), setter, attrs));
  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_ToObject) {
  // Runtime call is implemented in InterpreterIntrinsics and lowered in
  // JSIntrinsicLowering.
  UNREACHABLE();
}

RUNTIME_FUNCTION(Runtime_ToNumber) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  Handle<Object> input = args.at(0);
  RETURN_RESULT_OR_FAILURE(isolate, Object::ToNumber(isolate, input));
}

RUNTIME_FUNCTION(Runtime_ToNumeric) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  Handle<Object> input = args.at(0);
  RETURN_RESULT_OR_FAILURE(isolate, Object::ToNumeric(isolate, input));
}

RUNTIME_FUNCTION(Runtime_ToLength) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  Handle<Object> input = args.at(0);
  RETURN_RESULT_OR_FAILURE(isolate, Object::ToLength(isolate, input));
}

RUNTIME_FUNCTION(Runtime_ToString) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  Handle<Object> input = args.at(0);
  RETURN_RESULT_OR_FAILURE(isolate, Object::ToString(isolate, input));
}

RUNTIME_FUNCTION(Runtime_ToName) {
  HandleScope scope(isolate);
  DCHECK_EQ(1, args.length());
  Handle<Object> input = args.at(0);
  RETURN_RESULT_OR_FAILURE(isolate, Object::ToName(isolate, input));
}

RUNTIME_FUNCTION(Runtime_HasInPrototypeChain) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());
  Handle<Object> object = args.at(0);
  Handle<Object> prototype = args.at(1);
  if (!IsJSReceiver(*object)) return ReadOnlyRoots(isolate).false_value();
  Maybe<bool> result = JSReceiver::HasInPrototypeChain(
      isolate, Cast<JSReceiver>(object), prototype);
  MAYBE_RETURN(result, ReadOnlyRoots(isolate).exception());
  return isolate->heap()->ToBoolean(result.FromJust());
}

// ES6 section 7.4.7 CreateIterResultObject ( value, done )
RUNTIME_FUNCTION(Runtime_CreateIterResultObject) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());
  DirectHandle<Object> value = args.at(0);
  DirectHandle<Object> done = args.at(1);
  return *isolate->factory()->NewJSIteratorResult(
      value, Object::BooleanValue(*done, isolate));
}

RUNTIME_FUNCTION(Runtime_CreateDataProperty) {
  HandleScope scope(isolate);
  DCHECK_EQ(3, args.length());
  Handle<JSReceiver> o = args.at<JSReceiver>(0);
  Handle<Object> key = args.at(1);
  Handle<Object> value = args.at(2);
  bool success;
  PropertyKey lookup_key(isolate, key, &success);
  if (!success) return ReadOnlyRoots(isolate).exception();
  MAYBE_RETURN(JSReceiver::CreateDataProperty(isolate, o, lookup_key, value,
                                              Just(kThrowOnError)),
               ReadOnlyRoots(isolate).exception());
  return *value;
}

RUNTIME_FUNCTION(Runtime_SetOwnPropertyIgnoreAttributes) {
  HandleScope scope(isolate);
  DCHECK_EQ(4, args.length());
  Handle<JSObject> o = args.at<JSObject>(0);
  Handle<String> key = args.at<String>(1);
  Handle<Object> value = args.at(2);
  int attributes = args.smi_value_at(3);

  RETURN_RESULT_OR_FAILURE(isolate,
                           JSObject::SetOwnPropertyIgnoreAttributes(
                               o, key, value, PropertyAttributes(attributes)));
}

// Returns a PropertyDescriptorObject (property-descriptor-object.h)
RUNTIME_FUNCTION(Runtime_GetOwnPropertyDescriptorObject) {
  HandleScope scope(isolate);

  DCHECK_EQ(2, args.length());
  Handle<JSReceiver> object = args.at<JSReceiver>(0);
  Handle<Name> name = args.at<Name>(1);

  PropertyDescriptor desc;
  Maybe<bool> found =
      JSReceiver::GetOwnPropertyDescriptor(isolate, object, name, &desc);
  MAYBE_RETURN(found, ReadOnlyRoots(isolate).exception());

  if (!found.FromJust()) return ReadOnlyRoots(isolate).undefined_value();
  return *desc.ToPropertyDescriptorObject(isolate);
}

enum class PrivateMemberType {
  kPrivateField,
  kPrivateAccessor,
  kPrivateMethod,
};

struct PrivateMember {
  PrivateMemberType type;
  // It's the class constructor for static methods/accessors,
  // the brand symbol for instance methods/accessors,
  // and the private name symbol for fields.
  Handle<Object> brand_or_field_symbol;
  Handle<Object> value;
};

namespace {
void CollectPrivateMethodsAndAccessorsFromContext(
    Isolate* isolate, DirectHandle<Context> context, Handle<String> desc,
    Handle<Object> brand, IsStaticFlag is_static_flag,
    std::vector<PrivateMember>* results) {
  DirectHandle<ScopeInfo> scope_info(context->scope_info(), isolate);
  VariableLookupResult lookup_result;
  int context_index = scope_info->ContextSlotIndex(desc, &lookup_result);
  if (context_index == -1 ||
      !IsPrivateMethodOrAccessorVariableMode(lookup_result.mode) ||
      lookup_result.is_static_flag != is_static_flag) {
    return;
  }

  Handle<Object> slot_value(context->get(context_index), isolate);
  DCHECK_IMPLIES(lookup_result.mode == VariableMode::kPrivateMethod,
                 IsJSFunction(*slot_value));
  DCHECK_IMPLIES(lookup_result.mode != VariableMode::kPrivateMethod,
                 IsAccessorPair(*slot_value));
  results->push_back({
      lookup_result.mode == VariableMode::kPrivateMethod
          ? PrivateMemberType::kPrivateMethod
          : PrivateMemberType::kPrivateAccessor,
      brand,
      slot_value,
  });
}

Maybe<bool> CollectPrivateMembersFromReceiver(
    Isolate* isolate, Handle<JSReceiver> receiver, Handle<String> desc,
    std::vector<PrivateMember>* results) {
  PropertyFilter key_filter =
      static_cast<PropertyFilter>(PropertyFilter::PRIVATE_NAMES_ONLY);
  Handle<FixedArray> keys;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, keys,
      KeyAccumulator::GetKeys(isolate, receiver, KeyCollectionMode::kOwnOnly,
                              key_filter, GetKeysConversion::kConvertToString),
      Nothing<bool>());

  if (IsJSFunction(*receiver)) {
    Handle<JSFunction> func(Cast<JSFunction>(*receiver), isolate);
    DirectHandle<SharedFunctionInfo> shared(func->shared(), isolate);
    if (shared->is_class_constructor() &&
        shared->has_static_private_methods_or_accessors()) {
      DirectHandle<Context> receiver_context(
          Cast<JSFunction>(*receiver)->context(), isolate);
      CollectPrivateMethodsAndAccessorsFromContext(
          isolate, receiver_context, desc, func, IsStaticFlag::kStatic,
          results);
    }
  }

  for (int i = 0; i < keys->length(); ++i) {
    DirectHandle<Object> obj_key(keys->get(i), isolate);
    Handle<Symbol> symbol(Cast<Symbol>(*obj_key), isolate);
    CHECK(symbol->is_private_name());
    Handle<Object> value;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, value, Object::GetProperty(isolate, receiver, symbol),
        Nothing<bool>());

    if (symbol->is_private_brand()) {
      DirectHandle<Context> value_context(Cast<Context>(*value), isolate);
      CollectPrivateMethodsAndAccessorsFromContext(
          isolate, value_context, desc, symbol, IsStaticFlag::kNotStatic,
          results);
    } else {
      DirectHandle<String> symbol_desc(Cast<String>(symbol->description()),
                                       isolate);
      if (symbol_desc->Equals(*desc)) {
        results->push_back({
            PrivateMemberType::kPrivateField,
            symbol,
            value,
        });
      }
    }
  }

  return Just(true);
}

Maybe<bool> FindPrivateMembersFromReceiver(Isolate* isolate,
                                           Handle<JSReceiver> receiver,
                                           Handle<String> desc,
                                           MessageTemplate not_found_message,
                                           PrivateMember* result) {
  std::vector<PrivateMember> results;
  MAYBE_RETURN(
      CollectPrivateMembersFromReceiver(isolate, receiver, desc, &results),
      Nothing<bool>());

  if (results.empty()) {
    THROW_NEW_ERROR_RETURN_VALUE(isolate, NewError(not_found_message, desc),
                                 Nothing<bool>());
  } else if (results.size() > 1) {
    THROW_NEW_ERROR_RETURN_VALUE(
        isolate, NewError(MessageTemplate::kConflictingPrivateName, desc),
        Nothing<bool>());
  }

  *result = results[0];
  return Just(true);
}
}  // namespace

MaybeHandle<Object> Runtime::GetPrivateMember(Isolate* isolate,
                                              Handle<JSReceiver> receiver,
                                              Handle<String> desc) {
  PrivateMember result;
  MAYBE_RETURN_NULL(FindPrivateMembersFromReceiver(
      isolate, receiver, desc, MessageTemplate::kInvalidPrivateMemberRead,
      &result));

  switch (result.type) {
    case PrivateMemberType::kPrivateField:
    case PrivateMemberType::kPrivateMethod: {
      return result.value;
    }
    case PrivateMemberType::kPrivateAccessor: {
      // The accessors are collected from the contexts, so there is no need to
      // perform brand checks.
      auto pair = Cast<AccessorPair>(result.value);
      if (IsNull(pair->getter())) {
        THROW_NEW_ERROR(
            isolate,
            NewError(MessageTemplate::kInvalidPrivateGetterAccess, desc));
      }
      DCHECK(IsJSFunction(pair->getter()));
      Handle<JSFunction> getter(Cast<JSFunction>(pair->getter()), isolate);
      return Execution::Call(isolate, getter, receiver, 0, nullptr);
    }
  }
}

MaybeHandle<Object> Runtime::SetPrivateMember(Isolate* isolate,
                                              Handle<JSReceiver> receiver,
                                              Handle<String> desc,
                                              Handle<Object> value) {
  PrivateMember result;
  MAYBE_RETURN_NULL(FindPrivateMembersFromReceiver(
      isolate, receiver, desc, MessageTemplate::kInvalidPrivateMemberRead,
      &result));

  switch (result.type) {
    case PrivateMemberType::kPrivateField: {
      auto symbol = Cast<Symbol>(result.brand_or_field_symbol);
      return Object::SetProperty(isolate, receiver, symbol, value,
                                 StoreOrigin::kMaybeKeyed);
    }
    case PrivateMemberType::kPrivateMethod: {
      THROW_NEW_ERROR(
          isolate, NewError(MessageTemplate::kInvalidPrivateMethodWrite, desc));
    }
    case PrivateMemberType::kPrivateAccessor: {
      // The accessors are collected from the contexts, so there is no need to
      // perform brand checks.
      auto pair = Cast<AccessorPair>(result.value);
      if (IsNull(pair->setter())) {
        THROW_NEW_ERROR(
            isolate,
            NewError(MessageTemplate::kInvalidPrivateSetterAccess, desc));
      }
      DCHECK(IsJSFunction(pair->setter()));
      Handle<Object> argv[] = {value};
      Handle<JSFunction> setter(Cast<JSFunction>(pair->setter()), isolate);
      return Execution::Call(isolate, setter, receiver, arraysize(argv), argv);
    }
  }
}

RUNTIME_FUNCTION(Runtime_GetPrivateMember) {
  HandleScope scope(isolate);
  // TODO(chromium:1381806) support specifying scopes, or selecting the right
  // one from the conflicting names.
  DCHECK_EQ(args.length(), 2);
  Handle<Object> receiver = args.at<Object>(0);
  Handle<String> desc = args.at<String>(1);
  if (IsNullOrUndefined(*receiver, isolate)) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kNonObjectPrivateNameAccess,
                              desc, receiver));
  }
  RETURN_RESULT_OR_FAILURE(
      isolate,
      Runtime::GetPrivateMember(isolate, Cast<JSReceiver>(receiver), desc));
}

RUNTIME_FUNCTION(Runtime_SetPrivateMember) {
  HandleScope scope(isolate);
  // TODO(chromium:1381806) support specifying scopes, or selecting the right
  // one from the conflicting names.
  DCHECK_EQ(args.length(), 3);
  Handle<Object> receiver = args.at<Object>(0);
  Handle<String> desc = args.at<String>(1);
  if (IsNullOrUndefined(*receiver, isolate)) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kNonObjectPrivateNameAccess,
                              desc, receiver));
  }
  Handle<Object> value = args.at<Object>(2);
  RETURN_RESULT_OR_FAILURE(
      isolate, Runtime::SetPrivateMember(isolate, Cast<JSReceiver>(receiver),
                                         desc, value));
}

RUNTIME_FUNCTION(Runtime_LoadPrivateSetter) {
  HandleScope scope(isolate);
  DCHECK_EQ(args.length(), 1);
  DirectHandle<AccessorPair> pair = args.at<AccessorPair>(0);
  DCHECK(IsJSFunction(pair->setter()));
  return pair->setter();
}

RUNTIME_FUNCTION(Runtime_LoadPrivateGetter) {
  HandleScope scope(isolate);
  DCHECK_EQ(args.length(), 1);
  DirectHandle<AccessorPair> pair = args.at<AccessorPair>(0);
  DCHECK(IsJSFunction(pair->getter()));
  return pair->getter();
}

RUNTIME_FUNCTION(Runtime_CreatePrivateAccessors) {
  HandleScope scope(isolate);
  DCHECK_EQ(args.length(), 2);
  DCHECK(IsNull(args[0]) || IsJSFunction(args[0]));
  DCHECK(IsNull(args[1]) || IsJSFunction(args[1]));
  DirectHandle<AccessorPair> pair = isolate->factory()->NewAccessorPair();
  pair->SetComponents(args[0], args[1]);
  return *pair;
}

// TODO(v8:11330) This is only here while the CSA/Torque implementaton of
// SwissNameDictionary is work in progress.
RUNTIME_FUNCTION(Runtime_SwissTableAllocate) {
  HandleScope scope(isolate);
  int at_least_space_for = args.smi_value_at(0);

  return *isolate->factory()->NewSwissNameDictionary(at_least_space_for,
                                                     AllocationType::kYoung);
}

// TODO(v8:11330) This is only here while the CSA/Torque implementaton of
// SwissNameDictionary is work in progress.
RUNTIME_FUNCTION(Runtime_SwissTableAdd) {
  HandleScope scope(isolate);
  Handle<SwissNameDictionary> table = args.at<SwissNameDictionary>(0);
  DirectHandle<Name> key = args.at<Name>(1);
  DirectHandle<Object> value = args.at(2);
  PropertyDetails details(Cast<Smi>(args[3]));

  DCHECK(IsUniqueName(*key));

  return *SwissNameDictionary::Add(isolate, table, key, value, details);
}

// TODO(v8:11330) This is only here while the CSA/Torque implementaton of
// SwissNameDictionary is work in progress.
RUNTIME_FUNCTION(Runtime_SwissTableFindEntry) {
  HandleScope scope(isolate);
  DisallowGarbageCollection no_gc;
  auto table = Cast<SwissNameDictionary>(args[0]);
  Tagged<Name> key = Cast<Name>(args[1]);
  InternalIndex index = table->FindEntry(isolate, key);
  return Smi::FromInt(index.is_found()
                          ? index.as_int()
                          : SwissNameDictionary::kNotFoundSentinel);
}

// TODO(v8:11330) This is only here while the CSA/Torque implementaton of
// SwissNameDictionary is work in progress.
RUNTIME_FUNCTION(Runtime_SwissTableUpdate) {
  HandleScope scope(isolate);
  DisallowGarbageCollection no_gc;
  auto table = Cast<SwissNameDictionary>(args[0]);
  InternalIndex index(args.smi_value_at(1));
  Tagged<Object> value = args[2];
  table->ValueAtPut(index, value);

  PropertyDetails details(Cast<Smi>(args[3]));
  table->DetailsAtPut(index, details);

  return ReadOnlyRoots(isolate).undefined_value();
}

// TODO(v8:11330) This is only here while the CSA/Torque implementaton of
// SwissNameDictionary is work in progress.
RUNTIME_FUNCTION(Runtime_SwissTableDelete) {
  HandleScope scope(isolate);
  Handle<SwissNameDictionary> table = args.at<SwissNameDictionary>(0);
  InternalIndex index(args.smi_value_at(1));

  return *SwissNameDictionary::DeleteEntry(isolate, table, index);
}

// TODO(v8:11330) This is only here while the CSA/Torque implementaton of
// SwissNameDictionary is work in progress.
RUNTIME_FUNCTION(Runtime_SwissTableEquals) {
  HandleScope scope(isolate);
  DisallowGarbageCollection no_gc;
  auto table = Cast<SwissNameDictionary>(args[0]);
  auto other = Cast<SwissNameDictionary>(args[0]);
  return Smi::FromInt(table->EqualsForTesting(other));
}

// TODO(v8:11330) This is only here while the CSA/Torque implementaton of
// SwissNameDictionary is work in progress.
RUNTIME_FUNCTION(Runtime_SwissTableElementsCount) {
  HandleScope scope(isolate);
  DisallowGarbageCollection no_gc;
  auto table = Cast<SwissNameDictionary>(args[0]);
  return Smi::FromInt(table->NumberOfElements());
}

// TODO(v8:11330) This is only here while the CSA/Torque implementaton of
// SwissNameDictionary is work in progress.
RUNTIME_FUNCTION(Runtime_SwissTableKeyAt) {
  HandleScope scope(isolate);
  DisallowGarbageCollection no_gc;
  auto table = Cast<SwissNameDictionary>(args[0]);
  InternalIndex index(args.smi_value_at(1));
  return table->KeyAt(index);
}

// TODO(v8:11330) This is only here while the CSA/Torque implementaton of
// SwissNameDictionary is work in progress.
RUNTIME_FUNCTION(Runtime_SwissTableValueAt) {
  HandleScope scope(isolate);
  DisallowGarbageCollection no_gc;
  auto table = Cast<SwissNameDictionary>(args[0]);
  InternalIndex index(args.smi_value_at(1));
  return table->ValueAt(index);
}

// TODO(v8:11330) This is only here while the CSA/Torque implementaton of
// SwissNameDictionary is work in progress.
RUNTIME_FUNCTION(Runtime_SwissTableDetailsAt) {
  HandleScope scope(isolate);
  DisallowGarbageCollection no_gc;
  auto table = Cast<SwissNameDictionary>(args[0]);
  InternalIndex index(args.smi_value_at(1));
  PropertyDetails d = table->DetailsAt(index);
  return d.AsSmi();
}

}  // namespace internal
}  // namespace v8
```