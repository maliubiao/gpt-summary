Response:
My thought process to analyze the provided C++ code snippet and fulfill the prompt's requirements goes like this:

1. **Understand the Goal:** The primary goal is to analyze a specific part of the `v8/src/ic/ic.cc` file related to handling property access (specifically `LoadIC` and `KeyedLoadIC`) in V8 and summarize its functionality. The prompt also requests examples in JavaScript, logical reasoning with input/output, common programming errors, and information about `.tq` files.

2. **Identify Key Classes and Functions:**  I scan the code for significant class names and function calls. The core elements that jump out are:
    * `LoadIC`: This suggests handling property loads (like `object.property`).
    * `KeyedLoadIC`: This indicates handling indexed property loads (like `object[index]`).
    * `LookupIterator`: This class is used to traverse the prototype chain and find properties.
    * `LoadHandler`: This seems to be responsible for creating and managing IC (Inline Cache) handlers.
    * `MaybeObjectHandle`:  This is a common V8 type representing a handle to an object that might be null.
    * `Handle`: This is another crucial V8 type for managing garbage-collected objects.
    * `Map`: Represents the structure (shape) of JavaScript objects.
    * `AccessorPair`, `AccessorInfo`:  Deal with getter/setter properties.
    * `JSObject`, `JSArray`, `String`, `Symbol`, `JSProxy`:  Various JavaScript object types.
    * `ElementsKind`:  Describes the storage type for array elements.
    * `KeyedAccessLoadMode`:  Indicates how indexed access should be handled (e.g., handling holes, out-of-bounds access).
    * `UpdateLoadElement`, `LoadElementHandler`, `LoadElementPolymorphicHandlers`: Functions specifically related to indexed property loading.

3. **Break Down Functionality by Code Blocks:** I go through the code block by block, understanding what each part is doing:
    * **`LoadIC::ComputeHandler(LookupIterator* lookup)`:**  This is the central function for generating the appropriate IC handler based on the property lookup result. It handles various cases based on `lookup->state()`:
        * `ACCESSOR`:  Deals with getter/setter properties, including API accessors and template accessors.
        * `DATA`: Handles regular data properties, including constant properties and properties in dictionaries.
        * `TYPED_ARRAY_INDEX_NOT_FOUND`:  Handles cases where an index is out of bounds for a typed array.
        * `JSPROXY`:  Handles property access on Proxy objects.
        * Other cases (`WASM_OBJECT`, `ACCESS_CHECK`, etc.) are either not implemented or lead to slow paths.
    * **`KeyedLoadIC::GetKeyedAccessLoadModeFor(DirectHandle<Map> receiver_map)`:**  Retrieves the current keyed access load mode for a given object map.
    * **`KeyedLoadIC::UpdateLoadElement(...)`:**  Updates the IC state for indexed property loads, handling polymorphic cases (multiple object types).
    * **Helper functions (anonymous namespace):**  Functions like `AllowConvertHoleElementToUndefined`, `IsOutOfBoundsAccess`, `GetNewKeyedLoadMode`, and `TryConvertKey` provide supporting logic for keyed access.
    * **`KeyedLoadIC::LoadElementHandler(...)`:**  Generates the IC handler specifically for indexed property loads based on the object type and elements kind.
    * **`KeyedLoadIC::LoadElementPolymorphicHandlers(...)`:** Generates multiple handlers for polymorphic keyed access.
    * **`KeyedLoadIC::RuntimeLoad(...)`:**  Handles cases where the IC needs to fall back to the runtime system.
    * **`KeyedLoadIC::LoadName(...)`:** Handles loading named properties within the `KeyedLoadIC` context.
    * **`KeyedLoadIC::Load(...)`:** The main function for handling indexed property loads, coordinating the logic above.

4. **Connect Code to JavaScript Concepts:** For each major code section, I think about the corresponding JavaScript operations:
    * `LoadIC::ComputeHandler`: This directly relates to the `.` operator for property access in JavaScript (e.g., `object.property`).
    * `KeyedLoadIC`:  This corresponds to the `[]` operator for accessing properties by index or string key (e.g., `array[0]`, `object['key']`).
    * Accessors:  Maps to `get` and `set` keywords in JavaScript classes or object literals.
    * Proxies: The `Proxy` object in JavaScript.
    * Typed Arrays:  JavaScript's `Int32Array`, `Float64Array`, etc.

5. **Create JavaScript Examples:**  Based on the identified JavaScript concepts, I construct concise examples that illustrate the code's functionality. I focus on demonstrating different scenarios handled by the code (e.g., accessing regular properties, accessors, indexed properties, and the impact of the prototype chain).

6. **Develop Logical Reasoning (Input/Output):** I choose specific scenarios and trace the likely path through the code. I define a hypothetical input (JavaScript code) and predict the corresponding actions within the C++ code and the resulting output (the value of the accessed property or a change in the IC state).

7. **Identify Common Programming Errors:** I consider common mistakes JavaScript developers make that would trigger the logic in this code (e.g., accessing non-existent properties, accessing properties on `null` or `undefined`, incorrect use of proxies, and out-of-bounds array access).

8. **Address `.tq` Files:**  I know that `.tq` files are related to Torque, V8's domain-specific language for implementing built-in functions. I include this information.

9. **Synthesize the Summary:** Finally, I consolidate my understanding into a concise summary of the code's functionality, drawing upon the key classes, functions, and their connection to JavaScript. I focus on the role of `ic.cc` in optimizing property access through inline caching.

10. **Review and Refine:** I reread my analysis to ensure accuracy, clarity, and completeness, making sure it directly addresses all parts of the prompt. I check for any jargon that needs explanation and ensure the JavaScript examples are clear and relevant. I also double-check the input/output scenarios for correctness.
好的，我们来分析一下 `v8/src/ic/ic.cc` 代码片段的功能。

**代码功能归纳**

这段代码是 V8 引擎中 **Inline Cache (IC)** 机制的核心部分，专注于处理 **属性加载 (Load)** 操作，特别是当属性位于对象的 **原型链** 上时。它旨在优化 JavaScript 中属性访问的性能。

**具体功能分解**

1. **`LoadIC::ComputeHandler(LookupIterator* lookup)`:**  这是 `LoadIC` 的核心函数，负责根据属性查找的结果 (`LookupIterator`) 计算并返回一个用于加速后续相同属性访问的 **LoadHandler**。

   * **处理不同类型的属性：**  它根据 `lookup->state()` 的不同值，区分并处理各种情况：
      * **`LookupIterator::ACCESSOR` (访问器属性):**  处理 getter 函数的调用。它会检查是否是简单的字段访问、模块命名空间导出、或者需要调用 JavaScript 的 getter 函数。它还会考虑 API 调用的优化。
      * **`LookupIterator::DATA` (数据属性):** 处理直接存储在对象上的数据属性。包括在字典模式对象上的属性、以及优化后的字段访问。它还会处理常量属性的情况。
      * **`LookupIterator::TYPED_ARRAY_INDEX_NOT_FOUND` (类型化数组索引未找到):** 处理访问超出类型化数组边界的情况。
      * **`LookupIterator::JSPROXY` (代理对象):** 处理对 `Proxy` 对象的属性访问。
      * **其他情况:** 如 `WASM_OBJECT`、`ACCESS_CHECK` 等，通常会走较慢的路径。

   * **原型链查找优化:** 代码的核心逻辑在于处理当属性不在对象自身，而是在其原型链上时的情况。它尝试生成高效的 `LoadHandler`，以便后续访问可以直接跳到原型链上的正确位置。

2. **`KeyedAccessLoadMode` 相关:**  这部分定义和使用 `KeyedAccessLoadMode` 枚举，用于指示如何处理键值访问（例如数组访问）。不同的模式对应不同的优化策略，例如处理越界访问或访问空洞元素。

3. **`KeyedLoadIC::GetKeyedAccessLoadModeFor(DirectHandle<Map> receiver_map)`:**  获取指定对象 `Map` 的当前键值加载模式。

4. **`KeyedLoadIC::UpdateLoadElement(...)`:**  当执行键值加载时，更新 IC 的状态，以便为具有相同结构的后续访问生成更优化的处理程序。它会考虑对象的 `Map` 和当前的加载模式。

5. **匿名命名空间中的辅助函数:**  包含一些辅助函数，用于判断是否允许将空洞元素转换为 `undefined`，判断是否越界访问，以及根据对象类型和索引计算新的 `KeyedAccessLoadMode`。

6. **`KeyedLoadIC::LoadElementHandler(...)`:**  为键值加载创建一个 `LoadHandler`，考虑到各种对象类型（字符串、普通对象、代理对象、类型化数组等）和元素的存储方式。

7. **`KeyedLoadIC::LoadElementPolymorphicHandlers(...)`:**  处理多态情况下的键值加载，即当同一个调用点可能访问具有不同 `Map` 的对象时，生成一组 `LoadHandler`。

8. **`KeyedLoadIC::RuntimeLoad(...)`:**  当 IC 无法优化键值加载时，回退到运行时系统进行处理。

9. **`KeyedLoadIC::LoadName(...)`:**  在 `KeyedLoadIC` 的上下文中加载命名属性，实际上会调用 `LoadIC::Load`。

10. **`KeyedLoadIC::Load(...)`:**  `KeyedLoadIC` 的主要入口点，用于处理键值加载。它会尝试将键转换为数字索引或字符串名称，并根据情况调用相应的处理逻辑。

**V8 Torque 源代码 (.tq)**

如果 `v8/src/ic/ic.cc` 以 `.tq` 结尾，那么它确实是一个 V8 Torque 源代码。Torque 是 V8 内部使用的一种领域特定语言，用于更安全、更易于测试的方式编写性能关键的运行时代码和内置函数。这段代码片段不是 `.tq` 文件，因为它以 `.cc` 结尾，是 C++ 源代码。

**与 JavaScript 功能的关系 (Load 操作)**

这段代码直接对应 JavaScript 中的属性读取操作，例如：

```javascript
const obj = { a: 1, b: 2 };
const value = obj.a; // Load 操作

const arr = [10, 20, 30];
const element = arr[1]; // KeyedLoad 操作

function MyClass() {
  this.property = 5;
}
MyClass.prototype.protoProperty = 10;
const instance = new MyClass();
const protoValue = instance.protoProperty; // 原型链上的 Load 操作
```

**JavaScript 示例解释：**

* 当访问 `obj.a` 时，V8 会尝试使用 `LoadIC` 来优化这个操作。如果这是第一次访问，`ComputeHandler` 会分析对象 `obj` 的结构 (`Map`) 并生成一个 `LoadHandler`，以便下次访问 `obj.a` 可以更快地进行。
* 当访问 `arr[1]` 时，V8 会使用 `KeyedLoadIC`。代码会检查 `arr` 的元素类型和边界，以便选择合适的优化策略。
* 当访问 `instance.protoProperty` 时，`LoadIC` 会遍历 `instance` 的原型链，找到 `protoProperty` 并生成相应的 `LoadHandler`，以便后续访问可以直接定位到原型链上的属性。

**代码逻辑推理 (假设输入与输出)**

**假设输入 (JavaScript):**

```javascript
function Parent() {
  this.parentProp = "parent";
}
function Child() {
  this.childProp = "child";
}
Child.prototype = new Parent();

const myChild = new Child();
const value = myChild.parentProp;
```

**代码逻辑推理 (C++ 内部可能发生的事情):**

1. 当执行 `myChild.parentProp` 时，`LoadIC::Load` 被调用。
2. `LookupIterator` 开始在 `myChild` 对象上查找 `parentProp`。
3. 由于 `myChild` 自身没有 `parentProp`，`LookupIterator` 会沿着原型链向上查找，找到 `Child.prototype` (一个 `Parent` 实例)。
4. `LookupIterator` 继续向上查找，在 `Parent.prototype` 上找到了 `parentProp`。
5. `LoadIC::ComputeHandler` 被调用，`lookup->state()` 可能为 `LookupIterator::DATA`，表示找到了一个数据属性。
6. 由于属性位于原型链上，代码会尝试生成一个 `LoadHandler`，该 `LoadHandler` 记录了从 `myChild` 的 `Map` 到拥有 `parentProp` 的原型对象的路径 (涉及到 `Child` 的 `Map` 和 `Parent` 的 `Map`)。
7. **假设输出 (内部状态):**  IC 系统会为 `myChild` 对象的特定访问模式 (访问 `parentProp`) 缓存一个 `LoadHandler`。这个 `LoadHandler` 可能包含：
   * `myChild` 对象的 `Map` 信息。
   * `Parent.prototype` 对象的 `Map` 信息。
   * 到达 `parentProp` 的原型链偏移量。

**后续访问：** 如果再次执行 `myChild.parentProp`，V8 可以直接使用缓存的 `LoadHandler`，避免重复的原型链查找，从而提高性能。

**用户常见的编程错误**

1. **访问 `null` 或 `undefined` 的属性:**

   ```javascript
   let obj = null;
   const value = obj.a; // TypeError: Cannot read properties of null (reading 'a')
   ```

   这段代码会导致运行时错误，V8 的 IC 机制无法在这种情况下进行优化，因为对象本身无效。

2. **拼写错误的属性名:**

   ```javascript
   const obj = { myProperty: 10 };
   const value = obj.mProperty; // undefined
   ```

   IC 会尝试查找 `mProperty`，但由于属性不存在，最终会返回 `undefined`。虽然不会报错，但这通常是程序员的疏忽。

3. **在预期对象类型的地方使用了错误的对象类型:**

   ```javascript
   function process(obj) {
     return obj.value;
   }
   process(123); // 运行时可能不会报错，但结果可能不是预期的
   ```

   如果 `process` 函数期望接收一个具有 `value` 属性的对象，但实际传入的是一个原始类型，IC 的优化效果会受到影响，因为 V8 需要处理这种意外的情况。

**总结代码功能**

这段 `v8/src/ic/ic.cc` 代码的核心功能是 **优化 JavaScript 中对象属性的加载操作，特别是针对原型链上的属性**。它通过 **Inline Cache (IC)** 机制，在第一次属性访问时分析对象结构并生成优化的 `LoadHandler`，以便后续对相同属性的访问能够更快地执行。代码涵盖了对不同类型属性（数据属性、访问器属性）、不同对象类型（普通对象、代理对象、类型化数组）以及各种边界情况的处理。`KeyedLoadIC` 部分则专注于优化键值形式的属性加载（如数组访问）。

希望以上分析能够帮助你理解这段 V8 源代码的功能。

### 提示词
```
这是目录为v8/src/ic/ic.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/ic/ic.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
case LookupIterator::ACCESSOR: {
      Handle<JSObject> holder = lookup->GetHolder<JSObject>();
      // Use simple field loads for some well-known callback properties.
      // The method will only return true for absolute truths based on the
      // lookup start object maps.
      FieldIndex field_index;
      if (Accessors::IsJSObjectFieldAccessor(isolate(), map, lookup->name(),
                                             &field_index)) {
        TRACE_HANDLER_STATS(isolate(), LoadIC_LoadFieldDH);
        return MaybeObjectHandle(
            LoadHandler::LoadField(isolate(), field_index));
      }
      if (IsJSModuleNamespace(*holder)) {
        DirectHandle<ObjectHashTable> exports(
            Cast<JSModuleNamespace>(holder)->module()->exports(), isolate());
        InternalIndex entry =
            exports->FindEntry(isolate(), roots, lookup->name(),
                               Smi::ToInt(Object::GetHash(*lookup->name())));
        // We found the accessor, so the entry must exist.
        DCHECK(entry.is_found());
        int value_index = ObjectHashTable::EntryToValueIndex(entry);
        Handle<Smi> smi_handler =
            LoadHandler::LoadModuleExport(isolate(), value_index);
        if (holder_is_lookup_start_object) {
          return MaybeObjectHandle(smi_handler);
        }
        return MaybeObjectHandle(LoadHandler::LoadFromPrototype(
            isolate(), map, holder, *smi_handler));
      }

      Handle<Object> accessors = lookup->GetAccessors();
      if (IsAccessorPair(*accessors)) {
        Handle<AccessorPair> accessor_pair = Cast<AccessorPair>(accessors);
        if (lookup->TryLookupCachedProperty(accessor_pair)) {
          DCHECK_EQ(LookupIterator::DATA, lookup->state());
          return MaybeObjectHandle(ComputeHandler(lookup));
        }

        Handle<Object> getter(accessor_pair->getter(), isolate());
        if (!IsCallableJSFunction(*getter) &&
            !IsFunctionTemplateInfo(*getter)) {
          // TODO(jgruber): Update counter name.
          TRACE_HANDLER_STATS(isolate(), LoadIC_SlowStub);
          return MaybeObjectHandle(LoadHandler::LoadSlow(isolate()));
        }
        set_accessor(getter);

        if ((IsFunctionTemplateInfo(*getter) &&
             Cast<FunctionTemplateInfo>(*getter)->BreakAtEntry(isolate())) ||
            (IsJSFunction(*getter) &&
             Cast<JSFunction>(*getter)->shared()->BreakAtEntry(isolate()))) {
          // Do not install an IC if the api function has a breakpoint.
          TRACE_HANDLER_STATS(isolate(), LoadIC_SlowStub);
          return MaybeObjectHandle(LoadHandler::LoadSlow(isolate()));
        }

        Handle<Smi> smi_handler;

        CallOptimization call_optimization(isolate(), getter);
        if (call_optimization.is_simple_api_call()) {
          CallOptimization::HolderLookup holder_lookup;
          Handle<JSObject> api_holder =
              call_optimization.LookupHolderOfExpectedType(isolate(), map,
                                                           &holder_lookup);

          if (!call_optimization.IsCompatibleReceiverMap(api_holder, holder,
                                                         holder_lookup) ||
              !holder->HasFastProperties()) {
            TRACE_HANDLER_STATS(isolate(), LoadIC_SlowStub);
            return MaybeObjectHandle(LoadHandler::LoadSlow(isolate()));
          }

          smi_handler = LoadHandler::LoadApiGetter(
              isolate(), holder_lookup == CallOptimization::kHolderIsReceiver);

          Handle<NativeContext> accessor_context =
              GetAccessorContext(call_optimization, holder->map(), isolate());

          TRACE_HANDLER_STATS(isolate(), LoadIC_LoadApiGetterFromPrototypeDH);
          return MaybeObjectHandle(LoadHandler::LoadFromPrototype(
              isolate(), map, holder, *smi_handler,
              MaybeObjectHandle::Weak(call_optimization.api_call_info()),
              MaybeObjectHandle::Weak(accessor_context)));
        }

        if (holder->HasFastProperties()) {
          DCHECK(IsCallableJSFunction(*getter));
          if (holder_is_lookup_start_object) {
            TRACE_HANDLER_STATS(isolate(), LoadIC_LoadAccessorDH);
            return MaybeObjectHandle::Weak(accessor_pair);
          }
          TRACE_HANDLER_STATS(isolate(), LoadIC_LoadAccessorFromPrototypeDH);
          return MaybeObjectHandle(LoadHandler::LoadFromPrototype(
              isolate(), map, holder,
              *LoadHandler::LoadAccessorFromPrototype(isolate()),
              MaybeObjectHandle::Weak(getter)));
        }

        if (IsJSGlobalObject(*holder)) {
          TRACE_HANDLER_STATS(isolate(), LoadIC_LoadGlobalFromPrototypeDH);
          smi_handler = LoadHandler::LoadGlobal(isolate());
          return MaybeObjectHandle(LoadHandler::LoadFromPrototype(
              isolate(), map, holder, *smi_handler,
              MaybeObjectHandle::Weak(lookup->GetPropertyCell())));
        } else {
          smi_handler = LoadHandler::LoadNormal(isolate());
          TRACE_HANDLER_STATS(isolate(), LoadIC_LoadNormalDH);
          if (holder_is_lookup_start_object)
            return MaybeObjectHandle(smi_handler);
          TRACE_HANDLER_STATS(isolate(), LoadIC_LoadNormalFromPrototypeDH);
        }

        return MaybeObjectHandle(LoadHandler::LoadFromPrototype(
            isolate(), map, holder, *smi_handler));
      }

      DirectHandle<AccessorInfo> info = Cast<AccessorInfo>(accessors);

      if (info->replace_on_access()) {
        set_slow_stub_reason(
            "getter needs to be reconfigured to data property");
        TRACE_HANDLER_STATS(isolate(), LoadIC_SlowStub);
        return MaybeObjectHandle(LoadHandler::LoadSlow(isolate()));
      }

      if (!info->has_getter(isolate()) || !holder->HasFastProperties() ||
          (info->is_sloppy() && !IsJSReceiver(*receiver))) {
        TRACE_HANDLER_STATS(isolate(), LoadIC_SlowStub);
        return MaybeObjectHandle(LoadHandler::LoadSlow(isolate()));
      }

      Handle<Smi> smi_handler = LoadHandler::LoadNativeDataProperty(
          isolate(), lookup->GetAccessorIndex());
      TRACE_HANDLER_STATS(isolate(), LoadIC_LoadNativeDataPropertyDH);
      if (holder_is_lookup_start_object) return MaybeObjectHandle(smi_handler);
      TRACE_HANDLER_STATS(isolate(),
                          LoadIC_LoadNativeDataPropertyFromPrototypeDH);
      return MaybeObjectHandle(
          LoadHandler::LoadFromPrototype(isolate(), map, holder, *smi_handler));
    }

    case LookupIterator::DATA: {
      Handle<JSReceiver> holder = lookup->GetHolder<JSReceiver>();
      DCHECK_EQ(PropertyKind::kData, lookup->property_details().kind());
      Handle<Smi> smi_handler;
      if (lookup->is_dictionary_holder()) {
        if (IsJSGlobalObject(*holder, isolate())) {
          // TODO(verwaest): Also supporting the global object as receiver is a
          // workaround for code that leaks the global object.
          TRACE_HANDLER_STATS(isolate(), LoadIC_LoadGlobalDH);
          smi_handler = LoadHandler::LoadGlobal(isolate());
          return MaybeObjectHandle(LoadHandler::LoadFromPrototype(
              isolate(), map, holder, *smi_handler,
              MaybeObjectHandle::Weak(lookup->GetPropertyCell())));
        }
        smi_handler = LoadHandler::LoadNormal(isolate());
        TRACE_HANDLER_STATS(isolate(), LoadIC_LoadNormalDH);
        if (holder_is_lookup_start_object)
          return MaybeObjectHandle(smi_handler);
        TRACE_HANDLER_STATS(isolate(), LoadIC_LoadNormalFromPrototypeDH);
      } else if (lookup->IsElement(*holder)) {
        TRACE_HANDLER_STATS(isolate(), LoadIC_SlowStub);
        return MaybeObjectHandle(LoadHandler::LoadSlow(isolate()));
      } else {
        DCHECK_EQ(PropertyLocation::kField,
                  lookup->property_details().location());
        DCHECK(IsJSObject(*holder, isolate()));
        FieldIndex field = lookup->GetFieldIndex();
        smi_handler = LoadHandler::LoadField(isolate(), field);
        TRACE_HANDLER_STATS(isolate(), LoadIC_LoadFieldDH);
        if (holder_is_lookup_start_object)
          return MaybeObjectHandle(smi_handler);
        TRACE_HANDLER_STATS(isolate(), LoadIC_LoadFieldFromPrototypeDH);
      }
      if (lookup->constness() == PropertyConstness::kConst &&
          !holder_is_lookup_start_object) {
        DCHECK_IMPLIES(!V8_DICT_PROPERTY_CONST_TRACKING_BOOL,
                       !lookup->is_dictionary_holder());

        DirectHandle<Object> value = lookup->GetDataValue();

        if (IsThinString(*value)) {
          value = handle(Cast<ThinString>(*value)->actual(), isolate());
        }

        // Non internalized strings could turn into thin/cons strings
        // when internalized. Weak references to thin/cons strings are
        // not supported in the GC. If concurrent marking is running
        // and the thin/cons string is marked but the actual string is
        // not, then the weak reference could be missed.
        if (!IsString(*value) ||
            (IsString(*value) && IsInternalizedString(*value))) {
          MaybeObjectHandle weak_value =
              IsSmi(*value) ? MaybeObjectHandle(*value, isolate())
                            : MaybeObjectHandle::Weak(*value, isolate());

          smi_handler = LoadHandler::LoadConstantFromPrototype(isolate());
          TRACE_HANDLER_STATS(isolate(), LoadIC_LoadConstantFromPrototypeDH);
          return MaybeObjectHandle(LoadHandler::LoadFromPrototype(
              isolate(), map, holder, *smi_handler, weak_value));
        }
      }
      return MaybeObjectHandle(
          LoadHandler::LoadFromPrototype(isolate(), map, holder, *smi_handler));
    }
    case LookupIterator::TYPED_ARRAY_INDEX_NOT_FOUND:
      TRACE_HANDLER_STATS(isolate(), LoadIC_LoadIntegerIndexedExoticDH);
      return MaybeObjectHandle(LoadHandler::LoadNonExistent(isolate()));

    case LookupIterator::JSPROXY: {
      // Private names on JSProxy is currently not supported.
      if (lookup->name()->IsPrivate()) {
        return MaybeObjectHandle(LoadHandler::LoadSlow(isolate()));
      }
      Handle<Smi> smi_handler = LoadHandler::LoadProxy(isolate());
      if (holder_is_lookup_start_object) return MaybeObjectHandle(smi_handler);

      Handle<JSProxy> holder_proxy = lookup->GetHolder<JSProxy>();
      return MaybeObjectHandle(LoadHandler::LoadFromPrototype(
          isolate(), map, holder_proxy, *smi_handler));
    }

    case LookupIterator::WASM_OBJECT:
      return MaybeObjectHandle(LoadHandler::LoadSlow(isolate()));
    case LookupIterator::ACCESS_CHECK:
    case LookupIterator::NOT_FOUND:
    case LookupIterator::TRANSITION:
      UNREACHABLE();
  }

  return MaybeObjectHandle(Handle<InstructionStream>::null());
}

KeyedAccessLoadMode KeyedLoadIC::GetKeyedAccessLoadModeFor(
    DirectHandle<Map> receiver_map) const {
  const MaybeObjectHandle& handler = nexus()->FindHandlerForMap(receiver_map);
  if (handler.is_null()) return KeyedAccessLoadMode::kInBounds;
  return LoadHandler::GetKeyedAccessLoadMode(*handler);
}

// Returns whether the load mode transition is allowed.
bool AllowedHandlerChange(KeyedAccessLoadMode old_mode,
                          KeyedAccessLoadMode new_mode) {
  // Only allow transitions to allow OOB or allow converting a hole to
  // undefined.
  using T = std::underlying_type<KeyedAccessLoadMode>::type;
  return ((static_cast<T>(old_mode) ^
           static_cast<T>(GeneralizeKeyedAccessLoadMode(old_mode, new_mode))) &
          0b11) != 0;
}

void KeyedLoadIC::UpdateLoadElement(Handle<HeapObject> receiver,
                                    const KeyedAccessLoadMode new_load_mode) {
  Handle<Map> receiver_map(receiver->map(), isolate());
  DCHECK(receiver_map->instance_type() !=
         JS_PRIMITIVE_WRAPPER_TYPE);  // Checked by caller.
  MapHandles target_receiver_maps;
  TargetMaps(&target_receiver_maps);

  if (target_receiver_maps.empty()) {
    Handle<Object> handler = LoadElementHandler(receiver_map, new_load_mode);
    return ConfigureVectorState(Handle<Name>(), receiver_map, handler);
  }

  for (Handle<Map> map : target_receiver_maps) {
    if (map.is_null()) continue;
    if (map->instance_type() == JS_PRIMITIVE_WRAPPER_TYPE) {
      set_slow_stub_reason("JSPrimitiveWrapper");
      return;
    }
    if (map->instance_type() == JS_PROXY_TYPE) {
      set_slow_stub_reason("JSProxy");
      return;
    }
  }

  // The first time a receiver is seen that is a transitioned version of the
  // previous monomorphic receiver type, assume the new ElementsKind is the
  // monomorphic type. This benefits global arrays that only transition
  // once, and all call sites accessing them are faster if they remain
  // monomorphic. If this optimistic assumption is not true, the IC will
  // miss again and it will become polymorphic and support both the
  // untransitioned and transitioned maps.
  if (state() == MONOMORPHIC) {
    if ((IsJSObject(*receiver) &&
         IsMoreGeneralElementsKindTransition(
             target_receiver_maps.at(0)->elements_kind(),
             Cast<JSObject>(receiver)->GetElementsKind())) ||
        IsWasmObject(*receiver)) {
      Handle<Object> handler = LoadElementHandler(receiver_map, new_load_mode);
      return ConfigureVectorState(Handle<Name>(), receiver_map, handler);
    }
  }

  DCHECK(state() != GENERIC);

  // Determine the list of receiver maps that this call site has seen,
  // adding the map that was just encountered.
  KeyedAccessLoadMode old_load_mode = KeyedAccessLoadMode::kInBounds;
  if (!AddOneReceiverMapIfMissing(&target_receiver_maps, receiver_map)) {
    old_load_mode = GetKeyedAccessLoadModeFor(receiver_map);
    if (!AllowedHandlerChange(old_load_mode, new_load_mode)) {
      set_slow_stub_reason("same map added twice");
      return;
    }
  }

  // If the maximum number of receiver maps has been exceeded, use the generic
  // version of the IC.
  if (static_cast<int>(target_receiver_maps.size()) >
      v8_flags.max_valid_polymorphic_map_count) {
    set_slow_stub_reason("max polymorph exceeded");
    return;
  }

  MaybeObjectHandles handlers;
  handlers.reserve(target_receiver_maps.size());
  KeyedAccessLoadMode load_mode =
      GeneralizeKeyedAccessLoadMode(old_load_mode, new_load_mode);
  LoadElementPolymorphicHandlers(&target_receiver_maps, &handlers, load_mode);
  if (target_receiver_maps.empty()) {
    Handle<Object> handler = LoadElementHandler(receiver_map, new_load_mode);
    ConfigureVectorState(Handle<Name>(), receiver_map, handler);
  } else if (target_receiver_maps.size() == 1) {
    ConfigureVectorState(Handle<Name>(), target_receiver_maps[0], handlers[0]);
  } else {
    ConfigureVectorState(Handle<Name>(),
                         MapHandlesSpan(target_receiver_maps.begin(),
                                        target_receiver_maps.end()),
                         &handlers);
  }
}

namespace {

bool AllowConvertHoleElementToUndefined(Isolate* isolate,
                                        DirectHandle<Map> receiver_map) {
  if (IsJSTypedArrayMap(*receiver_map)) {
    // For JSTypedArray we never lookup elements in the prototype chain.
    return true;
  }

  // For other {receiver}s we need to check the "no elements" protector.
  if (Protectors::IsNoElementsIntact(isolate)) {
    if (IsStringMap(*receiver_map)) {
      return true;
    }
    if (IsJSObjectMap(*receiver_map)) {
      // For other JSObjects (including JSArrays) we can only continue if
      // the {receiver}s prototype is either the initial Object.prototype
      // or the initial Array.prototype, which are both guarded by the
      // "no elements" protector checked above.
      DirectHandle<HeapObject> receiver_prototype(receiver_map->prototype(),
                                                  isolate);
      InstanceType prototype_type = receiver_prototype->map()->instance_type();
      if (prototype_type == JS_OBJECT_PROTOTYPE_TYPE ||
          (prototype_type == JS_ARRAY_TYPE &&
           isolate->IsInCreationContext(
               Cast<JSObject>(*receiver_prototype),
               Context::INITIAL_ARRAY_PROTOTYPE_INDEX))) {
        return true;
      }
    }
  }

  return false;
}

bool IsOutOfBoundsAccess(DirectHandle<Object> receiver, size_t index) {
  size_t length;
  if (IsJSArray(*receiver)) {
    length = Object::NumberValue(Cast<JSArray>(*receiver)->length());
  } else if (IsJSTypedArray(*receiver)) {
    length = Cast<JSTypedArray>(*receiver)->GetLength();
  } else if (IsJSObject(*receiver)) {
    length = Cast<JSObject>(*receiver)->elements()->length();
  } else if (IsString(*receiver)) {
    length = Cast<String>(*receiver)->length();
  } else {
    return false;
  }
  return index >= length;
}

bool AllowReadingHoleElement(ElementsKind elements_kind) {
  return IsHoleyElementsKind(elements_kind);
}

KeyedAccessLoadMode GetNewKeyedLoadMode(Isolate* isolate,
                                        Handle<HeapObject> receiver,
                                        size_t index, bool is_found) {
  DirectHandle<Map> receiver_map(Cast<HeapObject>(receiver)->map(), isolate);
  if (!AllowConvertHoleElementToUndefined(isolate, receiver_map)) {
    return KeyedAccessLoadMode::kInBounds;
  }

  // Always handle holes when the elements kind is HOLEY_ELEMENTS, since the
  // optimizer compilers can not benefit from this information to narrow the
  // type. That is, the load type will always just be a generic tagged value.
  // This avoid an IC miss if we see a hole.
  ElementsKind elements_kind = receiver_map->elements_kind();
  bool always_handle_holes = (elements_kind == HOLEY_ELEMENTS);

  // In bound access and did not read a hole.
  if (is_found) {
    return always_handle_holes ? KeyedAccessLoadMode::kHandleHoles
                               : KeyedAccessLoadMode::kInBounds;
  }

  // OOB access.
  bool is_oob_access = IsOutOfBoundsAccess(receiver, index);
  if (is_oob_access) {
    return always_handle_holes ? KeyedAccessLoadMode::kHandleOOBAndHoles
                               : KeyedAccessLoadMode::kHandleOOB;
  }

  // Read a hole.
  DCHECK(!is_found && !is_oob_access);
  bool handle_hole = AllowReadingHoleElement(elements_kind);
  DCHECK_IMPLIES(always_handle_holes, handle_hole);
  return handle_hole ? KeyedAccessLoadMode::kHandleHoles
                     : KeyedAccessLoadMode::kInBounds;
}

KeyedAccessLoadMode GetUpdatedLoadModeForMap(Isolate* isolate,
                                             DirectHandle<Map> map,
                                             KeyedAccessLoadMode load_mode) {
  // If we are not allowed to convert a hole to undefined, then we should not
  // handle OOB nor reading holes.
  if (!AllowConvertHoleElementToUndefined(isolate, map)) {
    return KeyedAccessLoadMode::kInBounds;
  }
  // Check if the elements kind allow reading a hole.
  bool allow_reading_hole_element =
      AllowReadingHoleElement(map->elements_kind());
  switch (load_mode) {
    case KeyedAccessLoadMode::kInBounds:
    case KeyedAccessLoadMode::kHandleOOB:
      return load_mode;
    case KeyedAccessLoadMode::kHandleHoles:
      return allow_reading_hole_element ? KeyedAccessLoadMode::kHandleHoles
                                        : KeyedAccessLoadMode::kInBounds;
    case KeyedAccessLoadMode::kHandleOOBAndHoles:
      return allow_reading_hole_element
                 ? KeyedAccessLoadMode::kHandleOOBAndHoles
                 : KeyedAccessLoadMode::kHandleOOB;
  }
}

}  // namespace

Handle<Object> KeyedLoadIC::LoadElementHandler(
    DirectHandle<Map> receiver_map, KeyedAccessLoadMode new_load_mode) {
  // Has a getter interceptor, or is any has and has a query interceptor.
  if (receiver_map->has_indexed_interceptor() &&
      (!IsUndefined(receiver_map->GetIndexedInterceptor()->getter(),
                    isolate()) ||
       (IsAnyHas() &&
        !IsUndefined(receiver_map->GetIndexedInterceptor()->query(),
                     isolate()))) &&
      !receiver_map->GetIndexedInterceptor()->non_masking()) {
    // TODO(jgruber): Update counter name.
    TRACE_HANDLER_STATS(isolate(), KeyedLoadIC_LoadIndexedInterceptorStub);
    return IsAnyHas() ? BUILTIN_CODE(isolate(), HasIndexedInterceptorIC)
                      : BUILTIN_CODE(isolate(), LoadIndexedInterceptorIC);
  }

  InstanceType instance_type = receiver_map->instance_type();
  if (instance_type < FIRST_NONSTRING_TYPE) {
    TRACE_HANDLER_STATS(isolate(), KeyedLoadIC_LoadIndexedStringDH);
    if (IsAnyHas()) return LoadHandler::LoadSlow(isolate());
    return LoadHandler::LoadIndexedString(isolate(), new_load_mode);
  }
  if (instance_type < FIRST_JS_RECEIVER_TYPE) {
    TRACE_HANDLER_STATS(isolate(), KeyedLoadIC_SlowStub);
    return LoadHandler::LoadSlow(isolate());
  }
  if (instance_type == JS_PROXY_TYPE) {
    return LoadHandler::LoadProxy(isolate());
  }
#if V8_ENABLE_WEBASSEMBLY
  if (InstanceTypeChecker::IsWasmObject(instance_type)) {
    // TODO(jgruber): Update counter name.
    TRACE_HANDLER_STATS(isolate(), KeyedLoadIC_SlowStub);
    return LoadHandler::LoadSlow(isolate());
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  ElementsKind elements_kind = receiver_map->elements_kind();
  if (IsSloppyArgumentsElementsKind(elements_kind)) {
    // TODO(jgruber): Update counter name.
    TRACE_HANDLER_STATS(isolate(), KeyedLoadIC_KeyedLoadSloppyArgumentsStub);
    return IsAnyHas() ? BUILTIN_CODE(isolate(), KeyedHasIC_SloppyArguments)
                      : BUILTIN_CODE(isolate(), KeyedLoadIC_SloppyArguments);
  }
  bool is_js_array = instance_type == JS_ARRAY_TYPE;
  if (elements_kind == DICTIONARY_ELEMENTS) {
    TRACE_HANDLER_STATS(isolate(), KeyedLoadIC_LoadElementDH);
    return LoadHandler::LoadElement(isolate(), elements_kind, is_js_array,
                                    new_load_mode);
  }
  DCHECK(IsFastElementsKind(elements_kind) ||
         IsAnyNonextensibleElementsKind(elements_kind) ||
         IsTypedArrayOrRabGsabTypedArrayElementsKind(elements_kind));
  DCHECK_IMPLIES(
      LoadModeHandlesHoles(new_load_mode),
      AllowReadingHoleElement(elements_kind) &&
          AllowConvertHoleElementToUndefined(isolate(), receiver_map));
  TRACE_HANDLER_STATS(isolate(), KeyedLoadIC_LoadElementDH);
  return LoadHandler::LoadElement(isolate(), elements_kind, is_js_array,
                                  new_load_mode);
}

void KeyedLoadIC::LoadElementPolymorphicHandlers(
    MapHandles* receiver_maps, MaybeObjectHandles* handlers,
    KeyedAccessLoadMode new_load_mode) {
  // Filter out deprecated maps to ensure their instances get migrated.
  receiver_maps->erase(
      std::remove_if(
          receiver_maps->begin(), receiver_maps->end(),
          [](const DirectHandle<Map>& map) { return map->is_deprecated(); }),
      receiver_maps->end());

  for (DirectHandle<Map> receiver_map : *receiver_maps) {
    // Mark all stable receiver maps that have elements kind transition map
    // among receiver_maps as unstable because the optimizing compilers may
    // generate an elements kind transition for this kind of receivers.
    if (receiver_map->is_stable()) {
      Tagged<Map> tmap = receiver_map->FindElementsKindTransitionedMap(
          isolate(),
          MapHandlesSpan(receiver_maps->begin(), receiver_maps->end()),
          ConcurrencyMode::kSynchronous);
      if (!tmap.is_null()) {
        receiver_map->NotifyLeafMapLayoutChange(isolate());
      }
    }
    handlers->push_back(MaybeObjectHandle(LoadElementHandler(
        receiver_map,
        GetUpdatedLoadModeForMap(isolate(), receiver_map, new_load_mode))));
  }
}

namespace {

enum KeyType { kIntPtr, kName, kBailout };

// The cases where kIntPtr is returned must match what
// CodeStubAssembler::TryToIntptr can handle!
KeyType TryConvertKey(Handle<Object> key, Isolate* isolate, intptr_t* index_out,
                      Handle<Name>* name_out) {
  if (IsSmi(*key)) {
    *index_out = Smi::ToInt(*key);
    return kIntPtr;
  }
  if (IsHeapNumber(*key)) {
    double num = Cast<HeapNumber>(*key)->value();
    if (!(num >= -kMaxSafeInteger)) return kBailout;
    if (num > kMaxSafeInteger) return kBailout;
    *index_out = static_cast<intptr_t>(num);
    if (*index_out != num) return kBailout;
    return kIntPtr;
  }
  if (IsString(*key)) {
    key = isolate->factory()->InternalizeString(Cast<String>(key));
    uint32_t maybe_array_index;
    if (Cast<String>(*key)->AsArrayIndex(&maybe_array_index)) {
      if (maybe_array_index <= INT_MAX) {
        *index_out = static_cast<intptr_t>(maybe_array_index);
        return kIntPtr;
      }
      // {key} is a string representation of an array index beyond the range
      // that the IC could handle. Don't try to take the named-property path.
      return kBailout;
    }
    *name_out = Cast<String>(key);
    return kName;
  }
  if (IsSymbol(*key)) {
    *name_out = Cast<Symbol>(key);
    return kName;
  }
  return kBailout;
}

bool IntPtrKeyToSize(intptr_t index, DirectHandle<HeapObject> receiver,
                     size_t* out) {
  if (index < 0) {
    if (IsJSTypedArray(*receiver)) {
      // For JSTypedArray receivers, we can support negative keys, which we
      // just map to a very large value. This is valid because all OOB accesses
      // (negative or positive) are handled the same way, and size_t::max is
      // guaranteed to be an OOB access.
      *out = std::numeric_limits<size_t>::max();
      return true;
    }
    return false;
  }
#if V8_HOST_ARCH_64_BIT
  if (index > JSObject::kMaxElementIndex && !IsJSTypedArray(*receiver)) {
    return false;
  }
#else
  // On 32-bit platforms, any intptr_t is less than kMaxElementIndex.
  static_assert(
      static_cast<double>(std::numeric_limits<decltype(index)>::max()) <=
      static_cast<double>(JSObject::kMaxElementIndex));
#endif
  *out = static_cast<size_t>(index);
  return true;
}

bool CanCache(DirectHandle<Object> receiver, InlineCacheState state) {
  if (!v8_flags.use_ic || state == NO_FEEDBACK) return false;
  if (!IsJSReceiver(*receiver) && !IsString(*receiver)) return false;
  return !IsAccessCheckNeeded(*receiver) && !IsJSPrimitiveWrapper(*receiver);
}

}  // namespace

MaybeHandle<Object> KeyedLoadIC::RuntimeLoad(Handle<JSAny> object,
                                             Handle<Object> key,
                                             bool* is_found) {
  Handle<Object> result;

  if (IsKeyedLoadIC()) {
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate(), result,
        Runtime::GetObjectProperty(isolate(), object, key, Handle<JSAny>(),
                                   is_found));
  } else {
    DCHECK(IsKeyedHasIC());
    ASSIGN_RETURN_ON_EXCEPTION(isolate(), result,
                               Runtime::HasProperty(isolate(), object, key));
  }
  return result;
}

MaybeHandle<Object> KeyedLoadIC::LoadName(Handle<JSAny> object,
                                          DirectHandle<Object> key,
                                          Handle<Name> name) {
  Handle<Object> load_handle;
  ASSIGN_RETURN_ON_EXCEPTION(isolate(), load_handle,
                             LoadIC::Load(object, name));

  if (vector_needs_update()) {
    ConfigureVectorState(MEGAMORPHIC, key);
    TraceIC("LoadIC", key);
  }

  DCHECK(!load_handle.is_null());
  return load_handle;
}

MaybeHandle<Object> KeyedLoadIC::Load(Handle<JSAny> object,
                                      Handle<Object> key) {
  if (MigrateDeprecated(isolate(), object)) {
    return RuntimeLoad(object, key);
  }

  intptr_t maybe_index;
  Handle<Name> maybe_name;
  KeyType key_type = TryConvertKey(key, isolate(), &maybe_index, &maybe_name);

  if (key_type == kName) return LoadName(object, key, maybe_name);

  bool is_found = false;
  MaybeHandle<Object> result = RuntimeLoad(object, key, &is_found);

  size_t index;
  if (key_type == kIntPtr && CanCache(object, state()) &&
      IntPtrKeyToSize(maybe_index, Cast<HeapObject>(object), &index)) {
    Handle<HeapObject> receiver = Cast<HeapObject>(object);
    KeyedAccessLoadMode load_mode =
        GetNewKeyedLoadMode(isolate(), receiver, index, is_found);
    UpdateLoadElement(receiver, load_mode);
    if (is_vector_set()) {
      TraceIC("LoadIC", key);
    }
  }

  if (vector_needs_update()) {
    ConfigureVectorState(MEGAMORPHIC, key);
    TraceIC("LoadIC", key);
  }

  return result;
}

bool StoreIC::LookupForWrite(LookupIterator* it, DirectHandle<Object> value,
                             StoreOrigin store_origin) {
  // Disable ICs for non-JSObjects for now.
  Handle<Object> object = it->GetReceiver();
  if (IsJSProxy(*object)) return true;
  if (!IsJSObject(*object)) return false;
  Handle<JSObject> receiver = Cast<JSObject>(object);
  DCHECK(!receiver->map()->is_deprecated());

  for (;; it->Next()) {
    switch (it->state()) {
      case LookupIterator::TRANSITION:
        UNREACHABLE();
      case LookupIterator::WASM_OBJECT:
        return false;
      case LookupIterator::JSPROXY:
        return true;
      case LookupIterator::INTERCEPTOR: {
        DirectHandle<JSObject> holder = it->GetHolder<JSObject>();
        Tagged<InterceptorInfo> info = holder->GetNamedInterceptor();
        if (it->HolderIsReceiverOrHiddenPrototype() ||
            !IsUndefined(info->getter(), isolate()) ||
            !IsUndefined(info->query(), isolate())) {
          return true;
        }
        continue;
      }
      case LookupIterator::ACCESS_CHECK:
        if (IsAccessCheckNeeded(*it->GetHolder<JSObject>())) return false;
        continue;
      case LookupIterator::ACCESSOR:
        return !it->IsReadOnly();
      case LookupIterator::TYPED_ARRAY_INDEX_NOT_FOUND:
        return false;
      case LookupIterator::DATA: {
        if (it->IsReadOnly()) return false;
        if (IsAnyDefineOwn() && it->property_attributes() != NONE) {
          // IC doesn't support reconfiguration of property attributes,
          // so just bail out to the slow handler.
          return false;
        }
        Handle<JSObject> holder = it->GetHolder<JSObject>();
        if (receiver.is_identical_to(holder)) {
          it->PrepareForDataProperty(value);
          // The previous receiver map might just have been deprecated,
          // so reload it.
          update_lookup_start_object_map(receiver);
          return true;
        }

        // Receiver != holder.
        if (IsJSGlobalProxy(*receiver)) {
          PrototypeIterator iter(isolate(), receiver);
          return it->GetHolder<Object>().is_identical_to(
              PrototypeIterator::GetCurrent(iter));
        }

        if (it->HolderIsReceiverOrHiddenPrototype()) return false;

        if (it->ExtendingNonExtensible(receiver)) return false;
        it->PrepareTransitionToDataProperty(receiver, value, NONE,
                                            store_origin);
        return it->IsCacheableTransition();
      }
      case LookupIterator::NOT_FOUND:
        // If we are in StoreGlobal then check if we should throw on
        // non-existent properties.
        if (IsStoreGlobalIC() &&
            (GetShouldThrow(it->isolate(), Nothing<ShouldThrow>()) ==
             ShouldThrow::kThrowOnError)) {
          // ICs typically does the store in two steps: prepare receiver for the
          // transition followed by the actual store. For global objects we
          // create a property cell when preparing for transition and install
          // this cell in the handler. In strict mode, we throw and never
          // initialize this property cell. The IC handler assumes that the
          // property cell it is holding is for a property that is existing.
          // This case violates this assumption. If we happen to invalidate this
          // property cell later, it leads to incorrect behaviour. For now just
          // use a slow stub and don't install the property cell for these
          // cases. Hopefully these cases are not frequent enough to impact
          // performance.
          //
          // TODO(mythria): If we find this to be happening often, we could
          // install a new kind of handler for non-existent properties. These
          // handlers can then miss to runtime if the value is not hole (i.e.
          // cell got invalidated) and handle these stores correctly.
          return false;
        }
        receiver = it->GetStoreTarget<JSObject>();
        if (it->ExtendingNonExtensible(receiver)) return false;
        it->PrepareTransitionToDataProperty(receiver, value, NONE,
                                            store_origin);
        return it->IsCacheableTransition();
    }
    UNREACHABLE();
  }
}

MaybeHandle<Object> StoreGlobalIC::Store(Handle<Name> name,
                                         Handle<Object> value) {
  DCHECK(IsString(*name));
```