Response: The user wants a summary of the C++ code provided. This is the second part of a three-part file. The goal is to understand the functionality and illustrate its relationship with Javascript using examples if applicable.

Based on the code snippets, this part seems to deal primarily with the implementation of the `StoreIC` and `KeyedStoreIC` classes in V8. These classes are crucial for optimizing property assignment operations in Javascript.

Here's a breakdown of the key functionalities:

1. **`StoreIC::Store`**:  Handles storing properties on objects. It differentiates between storing on regular objects and global objects. It leverages inline caching (IC) to optimize subsequent stores to the same property. It also handles cases where the object is null/undefined and throws errors. It includes logic for defining own properties, considering attributes like writability, enumerability, and configurability.

2. **`StoreIC::UpdateCaches`**: Updates the IC's internal caches with information about the property store operation. This is where the optimization magic happens, storing handlers for fast subsequent access.

3. **`StoreIC::ComputeHandler`**: Determines the appropriate handler to use for a property store based on the object's state and property lookup results. This includes handling transitions between object shapes, interceptors, accessors, and regular data properties.

4. **`KeyedStoreIC::Store`**: Handles storing elements in objects using bracket notation (e.g., `obj[key] = value`). Similar to `StoreIC::Store`, it uses inline caching for optimization. It differentiates between various key types (strings, symbols, numbers).

5. **`KeyedStoreIC::UpdateStoreElement`**: Updates the IC's cache for keyed stores, considering different map transitions and elements kinds of the array.

6. **`KeyedStoreIC::StoreElementHandler`**: Determines the specific handler for keyed stores, considering elements kinds (fast, dictionary, etc.) and whether the array has read-only length.

7. **`KeyedStoreIC::StoreElementPolymorphicHandlers`**:  Manages the creation of polymorphic handlers for keyed stores, handling cases where the array might have different map types.

8. **`StoreInArrayLiteralIC::Store`**: Specifically handles storing elements in array literals during their initialization.

9. **Runtime Functions (e.g., `Runtime_LoadIC_Miss`, `Runtime_StoreIC_Miss`)**: These are runtime stubs that get called when the inline caches miss. They are responsible for updating the IC state and performing the actual property access.

The connection to Javascript is direct. Every time you assign a property to a Javascript object, these C++ classes are involved behind the scenes. The IC mechanism is a fundamental part of V8's performance optimization for Javascript.
这个C++代码文件（`ic.cc`的第二部分）主要负责 **实现V8引擎中用于优化对象属性存储操作的内联缓存（Inline Caching, IC）机制**。  它具体实现了 `StoreIC` 和 `KeyedStoreIC` 两个核心类，以及与数组字面量存储相关的 `StoreInArrayLiteralIC` 类。  这些类通过在运行时记录属性访问模式，生成优化的代码，从而加速后续相同的属性存储操作。

**主要功能归纳如下：**

1. **`StoreIC` 类：处理命名属性的存储操作。**
    *   `Store()` 方法是核心，负责处理向对象存储属性的请求。它会检查对象的类型、属性是否存在、是否需要进行原型链查找等，并根据情况更新内联缓存。
    *   它会区分存储到普通对象和全局对象的情况。
    *   它会处理属性定义（`IsAnyDefineOwn()`），包括定义新的数据属性，并考虑属性的特性（writable, enumerable, configurable）。
    *   `UpdateCaches()` 方法用于更新内联缓存，存储关于属性存储操作的信息，以便后续快速执行。
    *   `ComputeHandler()` 方法用于计算在特定情况下执行存储操作的最佳处理器（handler）。这包括处理对象形状的转换（transition）、拦截器（interceptor）、访问器（accessor）和普通数据属性等。

2. **`KeyedStoreIC` 类：处理通过索引或字符串键访问的属性存储操作（通常用于数组或类似数组的对象）。**
    *   `Store()` 方法处理通过键（可以是数字或字符串）存储属性的请求。
    *   `UpdateStoreElement()` 方法用于更新基于键的存储操作的内联缓存，考虑了对象的 Map 变化和元素类型。
    *   `StoreElementHandler()` 方法用于决定基于键的存储操作的具体处理器，考虑了元素的类型（例如，快速元素、字典元素等）和数组是否具有只读长度。
    *   `StoreElementPolymorphicHandlers()` 方法用于处理多态的基于键的存储处理器，当遇到具有不同 Map 的对象时使用。

3. **`StoreInArrayLiteralIC` 类：专门处理在数组字面量初始化期间的元素存储操作。**
    *   `Store()` 方法针对数组字面量提供优化的存储路径。

4. **Runtime 函数（例如 `Runtime_LoadIC_Miss`, `Runtime_StoreIC_Miss` 等）：** 这些是当内联缓存未命中时调用的运行时函数。它们负责执行慢速的属性查找和存储操作，并有机会更新内联缓存，以便将来可以快速执行相同的操作。

**与 JavaScript 的关系及示例：**

`StoreIC` 和 `KeyedStoreIC` 类直接对应于 JavaScript 中对对象属性进行赋值的操作。每当你在 JavaScript 中执行属性赋值时，V8 引擎内部就会调用这些 C++ 代码来执行和优化操作。

**JavaScript 示例：**

```javascript
// 示例 1: 使用 StoreIC (命名属性存储)
const obj = {};
obj.name = "Alice"; // 第一次存储，可能会触发 Runtime_StoreIC_Miss
obj.name = "Bob";   // 第二次存储，如果 IC 命中，会使用优化的处理器

// 示例 2: 使用 KeyedStoreIC (索引属性存储 - 数组)
const arr = [];
arr[0] = 10; // 第一次存储，可能会触发 Runtime_KeyedStoreIC_Miss
arr[0] = 20; // 第二次存储，如果 IC 命中，会使用优化的处理器

// 示例 3: 使用 KeyedStoreIC (字符串键属性存储)
const person = {};
person["age"] = 30; // 可能会触发 Runtime_KeyedStoreIC_Miss
person["age"] = 31; // 如果 IC 命中，会使用优化的处理器

// 示例 4: 使用 StoreInArrayLiteralIC (数组字面量初始化)
const numbers = [1, 2, 3]; // 在创建数组字面量时，会使用 StoreInArrayLiteralIC 进行优化
```

**解释：**

*   当第一次执行 `obj.name = "Alice"` 时，由于没有缓存信息，V8 可能会调用 `Runtime_StoreIC_Miss` 来处理这次存储操作。同时，它会收集关于这次操作的信息，例如对象的 Map 和属性的名称，并更新内联缓存。
*   当第二次执行 `obj.name = "Bob"` 时，如果对象的 Map 和属性名称与之前缓存的信息匹配，V8 就会使用之前生成的优化处理器，从而更快地完成存储操作，而无需再次进行完整的属性查找。
*   `KeyedStoreIC` 的工作原理类似，但它处理的是通过索引或字符串键访问的属性。
*   `StoreInArrayLiteralIC` 则专门用于优化数组字面量初始化时的元素赋值，例如 `const numbers = [1, 2, 3];`。

总而言之，`ic.cc` 的这部分代码是 V8 引擎实现高性能 JavaScript 的关键组成部分，它通过内联缓存技术显著加速了对象属性的存储操作。

Prompt: 
```
这是目录为v8/src/ic/ic.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共3部分，请归纳一下它的功能

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
  for (auto& [map, handler] : *receiver_maps_and_handlers) {
    receiver_maps.push_back(map);
    USE(handler);
  }
  for (size_t i = 0; i < receiver_maps_and_handlers->size(); i++) {
    Handle<Map> receiver_map = receiver_maps_and_handlers->at(i).first;
    DCHECK(!receiver_map->is_deprecated());
    MaybeObjectHandle old_handler = receiver_maps_and_handlers->at(i).second;
    Handle<Object> handler;
    Handle<Map> transition;

    if (receiver_map->instance_type() < FIRST_JS_RECEIVER_TYPE ||
        receiver_map->ShouldCheckForReadOnlyElementsInPrototypeChain(
            isolate())) {
      // TODO(mvstanton): Consider embedding store_mode in the state of the slow
      // keyed store ic for uniformity.
      TRACE_HANDLER_STATS(isolate(), KeyedStoreIC_SlowStub);
      handler = StoreHandler::StoreSlow(isolate());

    } else {
      {
        Tagged<Map> tmap = receiver_map->FindElementsKindTransitionedMap(
            isolate(),
            MapHandlesSpan(receiver_maps.begin(), receiver_maps.end()),
            ConcurrencyMode::kSynchronous);
        if (!tmap.is_null()) {
          if (receiver_map->is_stable()) {
            receiver_map->NotifyLeafMapLayoutChange(isolate());
          }
          transition = handle(tmap, isolate());
        }
      }

      MaybeHandle<UnionOf<Smi, Cell>> validity_cell;
      Tagged<HeapObject> old_handler_obj;
      if (!old_handler.is_null() &&
          (*old_handler).GetHeapObject(&old_handler_obj) &&
          IsDataHandler(old_handler_obj)) {
        validity_cell = handle(
            Cast<DataHandler>(old_handler_obj)->validity_cell(), isolate());
      }
      // TODO(mythria): Do not recompute the handler if we know there is no
      // change in the handler.
      // TODO(mvstanton): The code below is doing pessimistic elements
      // transitions. I would like to stop doing that and rely on Allocation
      // Site Tracking to do a better job of ensuring the data types are what
      // they need to be. Not all the elements are in place yet, pessimistic
      // elements transitions are still important for performance.
      if (!transition.is_null()) {
        TRACE_HANDLER_STATS(isolate(),
                            KeyedStoreIC_ElementsTransitionAndStoreStub);
        handler = StoreHandler::StoreElementTransition(
            isolate(), receiver_map, transition, store_mode, validity_cell);
      } else {
        handler = StoreElementHandler(receiver_map, store_mode, validity_cell);
      }
    }
    DCHECK(!handler.is_null());
    receiver_maps_and_handlers->at(i) =
        MapAndHandler(receiver_map, MaybeObjectHandle(handler));
  }
}

namespace {

bool MayHaveTypedArrayInPrototypeChain(Isolate* isolate,
                                       DirectHandle<JSObject> object) {
  for (PrototypeIterator iter(isolate, *object); !iter.IsAtEnd();
       iter.Advance()) {
    // Be conservative, don't walk into proxies.
    if (IsJSProxy(iter.GetCurrent())) return true;
    if (IsJSTypedArray(iter.GetCurrent())) return true;
  }
  return false;
}

KeyedAccessStoreMode GetStoreMode(DirectHandle<JSObject> receiver,
                                  size_t index) {
  bool oob_access = IsOutOfBoundsAccess(receiver, index);
  // Don't consider this a growing store if the store would send the receiver to
  // dictionary mode.
  bool allow_growth =
      IsJSArray(*receiver) && oob_access && index <= JSArray::kMaxArrayIndex &&
      !receiver->WouldConvertToSlowElements(static_cast<uint32_t>(index));
  if (allow_growth) {
    return KeyedAccessStoreMode::kGrowAndHandleCOW;
  }
  if (receiver->map()->has_typed_array_or_rab_gsab_typed_array_elements() &&
      oob_access) {
    return KeyedAccessStoreMode::kIgnoreTypedArrayOOB;
  }
  return receiver->elements()->IsCowArray() ? KeyedAccessStoreMode::kHandleCOW
                                            : KeyedAccessStoreMode::kInBounds;
}

}  // namespace

MaybeHandle<Object> KeyedStoreIC::Store(Handle<JSAny> object,
                                        Handle<Object> key,
                                        Handle<Object> value) {
  // TODO(verwaest): Let SetProperty do the migration, since storing a property
  // might deprecate the current map again, if value does not fit.
  if (MigrateDeprecated(isolate(), object)) {
    Handle<Object> result;
    // TODO(v8:12548): refactor DefineKeyedOwnIC as a subclass of StoreIC
    // so the logic doesn't get mixed here.
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate(), result,
        IsDefineKeyedOwnIC()
            ? Runtime::DefineObjectOwnProperty(isolate(), object, key, value,
                                               StoreOrigin::kNamed)
            : Runtime::SetObjectProperty(isolate(), object, key, value,
                                         StoreOrigin::kMaybeKeyed));
    return result;
  }

  Handle<Object> store_handle;

  intptr_t maybe_index;
  Handle<Name> maybe_name;
  KeyType key_type = TryConvertKey(key, isolate(), &maybe_index, &maybe_name);

  if (key_type == kName) {
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate(), store_handle,
        StoreIC::Store(object, maybe_name, value, StoreOrigin::kMaybeKeyed));
    if (vector_needs_update()) {
      if (ConfigureVectorState(MEGAMORPHIC, key)) {
        set_slow_stub_reason("unhandled internalized string key");
        TraceIC("StoreIC", key);
      }
    }
    return store_handle;
  }

  JSObject::MakePrototypesFast(object, kStartAtPrototype, isolate());

  // TODO(jkummerow): Refactor the condition logic here and below.
  bool use_ic = (state() != NO_FEEDBACK) && v8_flags.use_ic &&
                !IsStringWrapper(*object) && !IsAccessCheckNeeded(*object) &&
                !IsJSGlobalProxy(*object);
  if (use_ic && !IsSmi(*object)) {
    // Don't use ICs for maps of the objects in Array's prototype chain. We
    // expect to be able to trap element sets to objects with those maps in
    // the runtime to enable optimization of element hole access.
    DirectHandle<HeapObject> heap_object = Cast<HeapObject>(object);
    if (heap_object->map()->IsMapInArrayPrototypeChain(isolate())) {
      set_slow_stub_reason("map in array prototype");
      use_ic = false;
    }
#if V8_ENABLE_WEBASSEMBLY
    if (IsWasmObjectMap(heap_object->map())) {
      set_slow_stub_reason("wasm object");
      use_ic = false;
    }
#endif
  }

  Handle<Map> old_receiver_map;
  bool is_arguments = false;
  bool key_is_valid_index = (key_type == kIntPtr);
  KeyedAccessStoreMode store_mode = KeyedAccessStoreMode::kInBounds;
  if (use_ic && IsJSReceiver(*object) && key_is_valid_index) {
    DirectHandle<JSReceiver> receiver = Cast<JSReceiver>(object);
    old_receiver_map = handle(receiver->map(), isolate());
    is_arguments = IsJSArgumentsObject(*receiver);
    bool is_jsobject = IsJSObject(*receiver);
    size_t index;
    key_is_valid_index = IntPtrKeyToSize(maybe_index, receiver, &index);
    if (is_jsobject && !is_arguments && key_is_valid_index) {
      DirectHandle<JSObject> receiver_object = Cast<JSObject>(object);
      store_mode = GetStoreMode(receiver_object, index);
    }
  }

  DCHECK(store_handle.is_null());
  // TODO(v8:12548): refactor DefineKeyedOwnIC as a subclass of StoreIC
  // so the logic doesn't get mixed here.
  MaybeHandle<Object> result =
      IsDefineKeyedOwnIC()
          ? Runtime::DefineObjectOwnProperty(isolate(), object, key, value,
                                             StoreOrigin::kNamed)
          : Runtime::SetObjectProperty(isolate(), object, key, value,
                                       StoreOrigin::kMaybeKeyed);
  if (result.is_null()) {
    DCHECK(isolate()->has_exception());
    set_slow_stub_reason("failed to set property");
    use_ic = false;
  }
  if (use_ic) {
    if (!old_receiver_map.is_null()) {
      if (is_arguments) {
        set_slow_stub_reason("arguments receiver");
      } else if (IsJSArray(*object) && StoreModeCanGrow(store_mode) &&
                 JSArray::HasReadOnlyLength(Cast<JSArray>(object))) {
        set_slow_stub_reason("array has read only length");
      } else if (IsJSObject(*object) &&
                 MayHaveTypedArrayInPrototypeChain(isolate(),
                                                   Cast<JSObject>(object))) {
        // Make sure we don't handle this in IC if there's any JSTypedArray in
        // the {receiver}'s prototype chain, since that prototype is going to
        // swallow all stores that are out-of-bounds for said prototype, and we
        // just let the runtime deal with the complexity of this.
        set_slow_stub_reason("typed array in the prototype chain");
      } else if (key_is_valid_index) {
        if (old_receiver_map->is_abandoned_prototype_map()) {
          set_slow_stub_reason("receiver with prototype map");
        } else if (old_receiver_map->has_dictionary_elements() ||
                   !old_receiver_map
                        ->ShouldCheckForReadOnlyElementsInPrototypeChain(
                            isolate())) {
          // We should go generic if receiver isn't a dictionary, but our
          // prototype chain does have dictionary elements. This ensures that
          // other non-dictionary receivers in the polymorphic case benefit
          // from fast path keyed stores.
          DirectHandle<HeapObject> receiver = Cast<HeapObject>(object);
          UpdateStoreElement(old_receiver_map, store_mode,
                             handle(receiver->map(), isolate()));
        } else {
          set_slow_stub_reason("prototype with potentially read-only elements");
        }
      } else {
        set_slow_stub_reason("non-smi-like key");
      }
    } else {
      set_slow_stub_reason("non-JSObject receiver");
    }
  }

  if (vector_needs_update()) {
    ConfigureVectorState(MEGAMORPHIC, key);
  }
  TraceIC("StoreIC", key);

  return result;
}

namespace {
Maybe<bool> StoreOwnElement(Isolate* isolate, Handle<JSArray> array,
                            Handle<Object> index, Handle<Object> value) {
  DCHECK(IsNumber(*index));
  PropertyKey key(isolate, index);
  LookupIterator it(isolate, array, key, LookupIterator::OWN);

  MAYBE_RETURN(JSObject::DefineOwnPropertyIgnoreAttributes(
                   &it, value, NONE, Just(ShouldThrow::kThrowOnError)),
               Nothing<bool>());
  return Just(true);
}
}  // namespace

MaybeHandle<Object> StoreInArrayLiteralIC::Store(Handle<JSArray> array,
                                                 Handle<Object> index,
                                                 Handle<Object> value) {
  DCHECK(!array->map()->IsMapInArrayPrototypeChain(isolate()));
  DCHECK(IsNumber(*index));

  if (!v8_flags.use_ic || state() == NO_FEEDBACK ||
      MigrateDeprecated(isolate(), array)) {
    MAYBE_RETURN_NULL(StoreOwnElement(isolate(), array, index, value));
    TraceIC("StoreInArrayLiteralIC", index);
    return value;
  }

  // TODO(neis): Convert HeapNumber to Smi if possible?

  KeyedAccessStoreMode store_mode = KeyedAccessStoreMode::kInBounds;
  if (IsSmi(*index)) {
    DCHECK_GE(Smi::ToInt(*index), 0);
    uint32_t index32 = static_cast<uint32_t>(Smi::ToInt(*index));
    store_mode = GetStoreMode(array, index32);
  }

  Handle<Map> old_array_map(array->map(), isolate());
  MAYBE_RETURN_NULL(StoreOwnElement(isolate(), array, index, value));

  if (IsSmi(*index)) {
    DCHECK(!old_array_map->is_abandoned_prototype_map());
    UpdateStoreElement(old_array_map, store_mode,
                       handle(array->map(), isolate()));
  } else {
    set_slow_stub_reason("index out of Smi range");
  }

  if (vector_needs_update()) {
    ConfigureVectorState(MEGAMORPHIC, index);
  }
  TraceIC("StoreInArrayLiteralIC", index);
  return value;
}

// ----------------------------------------------------------------------------
// Static IC stub generators.
//
//
RUNTIME_FUNCTION(Runtime_LoadIC_Miss) {
  HandleScope scope(isolate);
  DCHECK_EQ(4, args.length());
  // Runtime functions don't follow the IC's calling convention.
  Handle<JSAny> receiver = args.at<JSAny>(0);
  Handle<Name> key = args.at<Name>(1);
  int slot = args.tagged_index_value_at(2);
  Handle<FeedbackVector> vector = args.at<FeedbackVector>(3);
  FeedbackSlot vector_slot = FeedbackVector::ToSlot(slot);

  // A monomorphic or polymorphic KeyedLoadIC with a string key can call the
  // LoadIC miss handler if the handler misses. Since the vector Nexus is
  // set up outside the IC, handle that here.
  FeedbackSlotKind kind = vector->GetKind(vector_slot);
  if (IsLoadICKind(kind)) {
    LoadIC ic(isolate, vector, vector_slot, kind);
    ic.UpdateState(receiver, key);
    RETURN_RESULT_OR_FAILURE(isolate, ic.Load(receiver, key));

  } else if (IsLoadGlobalICKind(kind)) {
    DCHECK_EQ(isolate->native_context()->global_proxy(), *receiver);
    receiver = isolate->global_object();
    LoadGlobalIC ic(isolate, vector, vector_slot, kind);
    ic.UpdateState(receiver, key);
    RETURN_RESULT_OR_FAILURE(isolate, ic.Load(key));

  } else {
    DCHECK(IsKeyedLoadICKind(kind));
    KeyedLoadIC ic(isolate, vector, vector_slot, kind);
    ic.UpdateState(receiver, key);
    RETURN_RESULT_OR_FAILURE(isolate, ic.Load(receiver, key));
  }
}

RUNTIME_FUNCTION(Runtime_LoadNoFeedbackIC_Miss) {
  HandleScope scope(isolate);
  DCHECK_EQ(3, args.length());
  // Runtime functions don't follow the IC's calling convention.
  Handle<JSAny> receiver = args.at<JSAny>(0);
  Handle<Name> key = args.at<Name>(1);
  int slot_kind = args.smi_value_at(2);
  FeedbackSlotKind kind = static_cast<FeedbackSlotKind>(slot_kind);

  Handle<FeedbackVector> vector = Handle<FeedbackVector>();
  FeedbackSlot vector_slot = FeedbackSlot::Invalid();
  // This function is only called after looking up in the ScriptContextTable so
  // it is safe to call LoadIC::Load for global loads as well.
  LoadIC ic(isolate, vector, vector_slot, kind);
  ic.UpdateState(receiver, key);
  RETURN_RESULT_OR_FAILURE(isolate, ic.Load(receiver, key));
}

RUNTIME_FUNCTION(Runtime_LoadWithReceiverNoFeedbackIC_Miss) {
  HandleScope scope(isolate);
  DCHECK_EQ(3, args.length());
  // Runtime functions don't follow the IC's calling convention.
  Handle<JSAny> receiver = args.at<JSAny>(0);
  Handle<JSAny> object = args.at<JSAny>(1);
  Handle<Name> key = args.at<Name>(2);

  Handle<FeedbackVector> vector = Handle<FeedbackVector>();
  FeedbackSlot vector_slot = FeedbackSlot::Invalid();
  LoadIC ic(isolate, vector, vector_slot, FeedbackSlotKind::kLoadProperty);
  ic.UpdateState(object, key);
  RETURN_RESULT_OR_FAILURE(isolate, ic.Load(object, key, true, receiver));
}

RUNTIME_FUNCTION(Runtime_LoadGlobalIC_Miss) {
  HandleScope scope(isolate);
  DCHECK_EQ(4, args.length());
  // Runtime functions don't follow the IC's calling convention.
  DirectHandle<JSGlobalObject> global = isolate->global_object();
  Handle<String> name = args.at<String>(0);
  int slot = args.tagged_index_value_at(1);
  Handle<HeapObject> maybe_vector = args.at<HeapObject>(2);
  int typeof_value = args.smi_value_at(3);
  TypeofMode typeof_mode = static_cast<TypeofMode>(typeof_value);
  FeedbackSlot vector_slot = FeedbackVector::ToSlot(slot);

  Handle<FeedbackVector> vector = Handle<FeedbackVector>();
  if (!IsUndefined(*maybe_vector, isolate)) {
    DCHECK(IsFeedbackVector(*maybe_vector));
    vector = Cast<FeedbackVector>(maybe_vector);
  }

  FeedbackSlotKind kind = (typeof_mode == TypeofMode::kInside)
                              ? FeedbackSlotKind::kLoadGlobalInsideTypeof
                              : FeedbackSlotKind::kLoadGlobalNotInsideTypeof;
  LoadGlobalIC ic(isolate, vector, vector_slot, kind);
  ic.UpdateState(global, name);

  Handle<Object> result;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, result, ic.Load(name));
  return *result;
}

RUNTIME_FUNCTION(Runtime_LoadGlobalIC_Slow) {
  HandleScope scope(isolate);
  DCHECK_EQ(3, args.length());
  Handle<String> name = args.at<String>(0);

  int slot = args.tagged_index_value_at(1);
  Handle<FeedbackVector> vector = args.at<FeedbackVector>(2);
  FeedbackSlot vector_slot = FeedbackVector::ToSlot(slot);
  FeedbackSlotKind kind = vector->GetKind(vector_slot);

  LoadGlobalIC ic(isolate, vector, vector_slot, kind);
  Handle<Object> result;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, result, ic.Load(name, false));
  return *result;
}

RUNTIME_FUNCTION(Runtime_LoadWithReceiverIC_Miss) {
  HandleScope scope(isolate);
  DCHECK_EQ(5, args.length());
  // Runtime functions don't follow the IC's calling convention.
  Handle<JSAny> receiver = args.at<JSAny>(0);
  Handle<JSAny> object = args.at<JSAny>(1);
  Handle<Name> key = args.at<Name>(2);
  int slot = args.tagged_index_value_at(3);
  Handle<FeedbackVector> vector = args.at<FeedbackVector>(4);
  FeedbackSlot vector_slot = FeedbackVector::ToSlot(slot);

  DCHECK(IsLoadICKind(vector->GetKind(vector_slot)));
  LoadIC ic(isolate, vector, vector_slot, FeedbackSlotKind::kLoadProperty);
  ic.UpdateState(object, key);
  RETURN_RESULT_OR_FAILURE(isolate, ic.Load(object, key, true, receiver));
}

RUNTIME_FUNCTION(Runtime_KeyedLoadIC_Miss) {
  HandleScope scope(isolate);
  DCHECK_EQ(4, args.length());
  // Runtime functions don't follow the IC's calling convention.
  Handle<JSAny> receiver = args.at<JSAny>(0);
  Handle<Object> key = args.at(1);
  int slot = args.tagged_index_value_at(2);
  Handle<HeapObject> maybe_vector = args.at<HeapObject>(3);

  Handle<FeedbackVector> vector = Handle<FeedbackVector>();
  if (!IsUndefined(*maybe_vector, isolate)) {
    DCHECK(IsFeedbackVector(*maybe_vector));
    vector = Cast<FeedbackVector>(maybe_vector);
  }
  FeedbackSlot vector_slot = FeedbackVector::ToSlot(slot);
  KeyedLoadIC ic(isolate, vector, vector_slot, FeedbackSlotKind::kLoadKeyed);
  ic.UpdateState(receiver, key);
  RETURN_RESULT_OR_FAILURE(isolate, ic.Load(receiver, key));
}

RUNTIME_FUNCTION(Runtime_StoreIC_Miss) {
  HandleScope scope(isolate);
  DCHECK_EQ(5, args.length());
  // Runtime functions don't follow the IC's calling convention.
  Handle<Object> value = args.at(0);
  int slot = args.tagged_index_value_at(1);
  Handle<HeapObject> maybe_vector = args.at<HeapObject>(2);
  Handle<JSAny> receiver = args.at<JSAny>(3);
  Handle<Name> key = args.at<Name>(4);

  FeedbackSlot vector_slot = FeedbackVector::ToSlot(slot);

  // When there is no feedback vector it is OK to use the SetNamedStrict as
  // the feedback slot kind. We only reuse this for DefineNamedOwnIC when
  // installing the handler for storing const properties. This will happen only
  // when feedback vector is available.
  FeedbackSlotKind kind = FeedbackSlotKind::kSetNamedStrict;
  Handle<FeedbackVector> vector = Handle<FeedbackVector>();
  if (!IsUndefined(*maybe_vector, isolate)) {
    DCHECK(IsFeedbackVector(*maybe_vector));
    DCHECK(!vector_slot.IsInvalid());
    vector = Cast<FeedbackVector>(maybe_vector);
    kind = vector->GetKind(vector_slot);
  }

  DCHECK(IsSetNamedICKind(kind) || IsDefineNamedOwnICKind(kind));
  StoreIC ic(isolate, vector, vector_slot, kind);
  ic.UpdateState(receiver, key);
  RETURN_RESULT_OR_FAILURE(isolate, ic.Store(receiver, key, value));
}

RUNTIME_FUNCTION(Runtime_DefineNamedOwnIC_Miss) {
  HandleScope scope(isolate);
  DCHECK_EQ(5, args.length());
  // Runtime functions don't follow the IC's calling convention.
  Handle<Object> value = args.at(0);
  int slot = args.tagged_index_value_at(1);
  Handle<HeapObject> maybe_vector = args.at<HeapObject>(2);
  Handle<JSAny> receiver = args.at<JSAny>(3);
  Handle<Name> key = args.at<Name>(4);

  FeedbackSlot vector_slot = FeedbackVector::ToSlot(slot);

  // When there is no feedback vector it is OK to use the DefineNamedOwn
  // feedback kind. There _should_ be a vector, though.
  FeedbackSlotKind kind = FeedbackSlotKind::kDefineNamedOwn;
  Handle<FeedbackVector> vector = Handle<FeedbackVector>();
  if (!IsUndefined(*maybe_vector, isolate)) {
    DCHECK(IsFeedbackVector(*maybe_vector));
    DCHECK(!vector_slot.IsInvalid());
    vector = Cast<FeedbackVector>(maybe_vector);
    kind = vector->GetKind(vector_slot);
  }

  DCHECK(IsDefineNamedOwnICKind(kind));

  // TODO(v8:12548): refactor DefineNamedOwnIC as a subclass of StoreIC, which
  // can be called here.
  StoreIC ic(isolate, vector, vector_slot, kind);
  ic.UpdateState(receiver, key);
  RETURN_RESULT_OR_FAILURE(isolate, ic.Store(receiver, key, value));
}

RUNTIME_FUNCTION(Runtime_DefineNamedOwnIC_Slow) {
  HandleScope scope(isolate);
  DCHECK_EQ(3, args.length());

  Handle<Object> value = args.at(0);
  Handle<JSAny> object = args.at<JSAny>(1);
  Handle<Object> key = args.at(2);

  // Unlike DefineKeyedOwnIC, DefineNamedOwnIC doesn't handle private
  // fields and is used for defining data properties in object literals
  // and defining named public class fields.
  DCHECK(!IsSymbol(*key) || !Cast<Symbol>(*key)->is_private_name());

  PropertyKey lookup_key(isolate, key);
  MAYBE_RETURN(JSReceiver::CreateDataProperty(isolate, object, lookup_key,
                                              value, Nothing<ShouldThrow>()),
               ReadOnlyRoots(isolate).exception());
  return *value;
}

RUNTIME_FUNCTION(Runtime_StoreGlobalIC_Miss) {
  HandleScope scope(isolate);
  DCHECK_EQ(4, args.length());
  // Runtime functions don't follow the IC's calling convention.
  Handle<Object> value = args.at(0);
  int slot = args.tagged_index_value_at(1);
  Handle<FeedbackVector> vector = args.at<FeedbackVector>(2);
  Handle<Name> key = args.at<Name>(3);

  FeedbackSlot vector_slot = FeedbackVector::ToSlot(slot);
  FeedbackSlotKind kind = vector->GetKind(vector_slot);
  StoreGlobalIC ic(isolate, vector, vector_slot, kind);
  DirectHandle<JSGlobalObject> global = isolate->global_object();
  ic.UpdateState(global, key);
  RETURN_RESULT_OR_FAILURE(isolate, ic.Store(key, value));
}

RUNTIME_FUNCTION(Runtime_StoreGlobalICNoFeedback_Miss) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());
  // Runtime functions don't follow the IC's calling convention.
  Handle<Object> value = args.at(0);
  Handle<Name> key = args.at<Name>(1);

  // TODO(mythria): Replace StoreGlobalStrict/Sloppy with SetNamedProperty.
  StoreGlobalIC ic(isolate, Handle<FeedbackVector>(), FeedbackSlot(),
                   FeedbackSlotKind::kStoreGlobalStrict);
  RETURN_RESULT_OR_FAILURE(isolate, ic.Store(key, value));
}

// TODO(mythria): Remove Feedback vector and slot. Since they are not used apart
// from the DCHECK.
RUNTIME_FUNCTION(Runtime_StoreGlobalIC_Slow) {
  HandleScope scope(isolate);
  DCHECK_EQ(5, args.length());
  // Runtime functions don't follow the IC's calling convention.
  Handle<Object> value = args.at(0);
  Handle<String> name = args.at<String>(4);

#ifdef DEBUG
  {
    int slot = args.tagged_index_value_at(1);
    DirectHandle<FeedbackVector> vector = args.at<FeedbackVector>(2);
    FeedbackSlot vector_slot = FeedbackVector::ToSlot(slot);
    FeedbackSlotKind slot_kind = vector->GetKind(vector_slot);
    DCHECK(IsStoreGlobalICKind(slot_kind));
    DirectHandle<JSAny> receiver = args.at<JSAny>(3);
    DCHECK(IsJSGlobalProxy(*receiver));
  }
#endif

  Handle<JSGlobalObject> global = isolate->global_object();
  DirectHandle<Context> native_context = isolate->native_context();
  DirectHandle<ScriptContextTable> script_contexts(
      native_context->script_context_table(), isolate);

  VariableLookupResult lookup_result;
  if (script_contexts->Lookup(name, &lookup_result)) {
    DirectHandle<Context> script_context(
        script_contexts->get(lookup_result.context_index), isolate);
    if (IsImmutableLexicalVariableMode(lookup_result.mode)) {
      THROW_NEW_ERROR_RETURN_FAILURE(
          isolate, NewTypeError(MessageTemplate::kConstAssign, global, name));
    }

    {
      DisallowGarbageCollection no_gc;
      Tagged<Object> previous_value =
          script_context->get(lookup_result.slot_index);

      if (IsTheHole(previous_value, isolate)) {
        AllowGarbageCollection yes_gc;
        THROW_NEW_ERROR_RETURN_FAILURE(
            isolate,
            NewReferenceError(MessageTemplate::kAccessedUninitializedVariable,
                              name));
      }
    }
    if (v8_flags.const_tracking_let) {
      Context::StoreScriptContextAndUpdateSlotProperty(
          script_context, lookup_result.slot_index, value, isolate);
    } else {
      script_context->set(lookup_result.slot_index, *value);
    }
    return *value;
  }

  RETURN_RESULT_OR_FAILURE(
      isolate, Runtime::SetObjectProperty(isolate, global, name, value,
                                          StoreOrigin::kMaybeKeyed));
}

RUNTIME_FUNCTION(Runtime_KeyedStoreIC_Miss) {
  HandleScope scope(isolate);
  DCHECK_EQ(5, args.length());
  // Runtime functions don't follow the IC's calling convention.
  Handle<Object> value = args.at(0);
  Handle<HeapObject> maybe_vector = args.at<HeapObject>(2);
  Handle<JSAny> receiver = args.at<JSAny>(3);
  Handle<Object> key = args.at(4);
  FeedbackSlot vector_slot;

  // When the feedback vector is not valid the slot can only be of type
  // StoreKeyed. Storing in array literals falls back to
  // StoreInArrayLiterIC_Miss. This function is also used from store handlers
  // installed in feedback vectors. In such cases, we need to get the kind from
  // feedback vector slot since the handlers are used for both for StoreKeyed
  // and StoreInArrayLiteral kinds.
  FeedbackSlotKind kind = FeedbackSlotKind::kSetKeyedStrict;
  Handle<FeedbackVector> vector = Handle<FeedbackVector>();
  if (!IsUndefined(*maybe_vector, isolate)) {
    DCHECK(IsFeedbackVector(*maybe_vector));
    vector = Cast<FeedbackVector>(maybe_vector);
    int slot = args.tagged_index_value_at(1);
    vector_slot = FeedbackVector::ToSlot(slot);
    kind = vector->GetKind(vector_slot);
  }

  // The elements store stubs miss into this function, but they are shared by
  // different ICs.
  // TODO(v8:12548): refactor DefineKeyedOwnIC as a subclass of KeyedStoreIC,
  // which can be called here.
  if (IsKeyedStoreICKind(kind) || IsDefineKeyedOwnICKind(kind)) {
    KeyedStoreIC ic(isolate, vector, vector_slot, kind);
    ic.UpdateState(receiver, key);
    RETURN_RESULT_OR_FAILURE(isolate, ic.Store(receiver, key, value));
  } else {
    DCHECK(IsStoreInArrayLiteralICKind(kind));
    DCHECK(IsJSArray(*receiver));
    DCHECK(IsNumber(*key));
    StoreInArrayLiteralIC ic(isolate, vector, vector_slot);
    ic.UpdateState(receiver, key);
    RETURN_RESULT_OR_FAILURE(isolate,
                             ic.Store(Cast<JSArray>(receiver), key, value));
  }
}

RUNTIME_FUNCTION(Runtime_DefineKeyedOwnIC_Miss) {
  HandleScope scope(isolate);
  DCHECK_EQ(5, args.length());
  // Runtime functions don't follow the IC's calling convention.
  Handle<Object> value = args.at(0);
  int slot = args.tagged_index_value_at(1);
  Handle<HeapObject> maybe_vector = args.at<HeapObject>(2);
  Handle<JSAny> receiver = args.at<JSAny>(3);
  Handle<Object> key = args.at(4);
  FeedbackSlot vector_slot = FeedbackVector::ToSlot(slot);

  FeedbackSlotKind kind = FeedbackSlotKind::kDefineKeyedOwn;
  Handle<FeedbackVector> vector = Handle<FeedbackVector>();
  if (!IsUndefined(*maybe_vector, isolate)) {
    DCHECK(IsFeedbackVector(*maybe_vector));
    vector = Cast<FeedbackVector>(maybe_vector);
    kind = vector->GetKind(vector_slot);
    DCHECK(IsDefineKeyedOwnICKind(kind));
  }

  // TODO(v8:12548): refactor DefineKeyedOwnIC as a subclass of KeyedStoreIC,
  // which can be called here.
  KeyedStoreIC ic(isolate, vector, vector_slot, kind);
  ic.UpdateState(receiver, key);
  RETURN_RESULT_OR_FAILURE(isolate, ic.Store(receiver, key, value));
}

RUNTIME_FUNCTION(Runtime_StoreInArrayLiteralIC_Miss) {
  HandleScope scope(isolate);
  DCHECK_EQ(5, args.length());
  // Runtime functions don't follow the IC's calling convention.
  Handle<Object> value = args.at(0);
  int slot = args.tagged_index_value_at(1);
  Handle<HeapObject> maybe_vector = args.at<HeapObject>(2);
  Handle<JSAny> receiver = args.at<JSAny>(3);
  Handle<Object> key = args.at(4);
  Handle<FeedbackVector> vector = Handle<FeedbackVector>();
  if (!IsUndefined(*maybe_vector, isolate)) {
    DCHECK(IsFeedbackVector(*maybe_vector));
    vector = Cast<FeedbackVector>(maybe_vector);
  }
  DCHECK(IsJSArray(*receiver));
  DCHECK(IsNumber(*key));
  FeedbackSlot vector_slot = FeedbackVector::ToSlot(slot);
  StoreInArrayLiteralIC ic(isolate, vector, vector_slot);
  RETURN_RESULT_OR_FAILURE(isolate,
                           ic.Store(Cast<JSArray>(receiver), key, value));
}

RUNTIME_FUNCTION(Runtime_KeyedStoreIC_Slow) {
  HandleScope scope(isolate);
  DCHECK_EQ(3, args.length());
  // Runtime functions don't follow the IC's calling convention.
  Handle<Object> value = args.at(0);
  Handle<JSAny> object = args.at<JSAny>(1);
  Handle<Object> key = args.at(2);
  RETURN_RESULT_OR_FAILURE(
      isolate, Runtime::SetObjectProperty(isolate, object, key, value,
                                          StoreOrigin::kMaybeKeyed));
}

RUNTIME_FUNCTION(Runtime_DefineKeyedOwnIC_Slow) {
  HandleScope scope(isolate);
  DCHECK_EQ(3, args.length());
  // Runtime functions don't follow the IC's calling convention.
  Handle<Object> value = args.at(0);
  Handle<JSAny> object = args.at<JSAny>(1);
  Handle<Object> key = args.at(2);
  RETURN_RESULT_OR_FAILURE(
      isolate, Runtime::DefineObjectOwnProperty(isolate, object, key, value,
                                                StoreOrigin::kNamed));
}

RUNTIME_FUNCTION(Runtime_StoreInArrayLiteralIC_Slow) {
  HandleScope scope(isolate);
  DCHECK_EQ(3, args.length());
  // Runtime functions don't follow the IC's calling convention.
  Handle<Object> value = args.at(0);
  Handle<Object> array = args.at(1);
  Handle<Object> index = args.at(2);
  StoreOwnElement(isolate, Cast<JSArray>(array), index, value);
  return *value;
}

RUNTIME_FUNCTION(Runtime_ElementsTransitionAndStoreIC_Miss) {
  HandleScope scope(isolate);
  DCHECK_EQ(6, args.length());
  // Runtime functions don't follow the IC's calling convention.
  Handle<JSAny> object = args.at<JSAny>(0);
  Handle<Object> key = args.at(1);
  Handle<Object> value = args.at(2);
  DirectHandle<Map> map = args.at<Map>(3);
  int slot = args.tagged_index_value_at(4);
  DirectHandle<FeedbackVector> vector = args.at<FeedbackVector>(5);
  FeedbackSlot vector_slot = FeedbackVector::ToSlot(slot);
  FeedbackSlotKind kind = vector->GetKind(vector_slot);

  if (IsJSObject(*object)) {
    JSObject::TransitionElementsKind(Cast<JSObject>(object),
                                     map->elements_kind());
  }

  if (IsStoreInArrayLiteralICKind(kind)) {
    StoreOwnElement(isolate, Cast<JSArray>(object), key, value);
    return *value;
  } else {
    DCHECK(IsKeyedStoreICKind(kind) || IsSetNamedICKind(kind) ||
           IsDefineKeyedOwnICKind(kind));
    RETURN_RESULT_OR_FAILURE(
        isolate, IsDefineKeyedOwnICKind(kind)
                     ? Runtime::DefineObjectOwnProperty(
                           isolate, object, key, value, StoreOrigin::kNamed)
                     : Runtime::SetObjectProperty(isolate, object, key, value,
                                                  StoreOrigin::kMaybeKeyed));
  }
}

namespace {

enum class FastCloneObjectMode {
  // The clone has the same map as the input.
  kIdenticalMap,
  // The clone is the empty object literal.
  kEmptyObject,
  // The clone has an empty object literal map.
  kDifferentMap,
  // The source map is to complicated to handle.
  kNotSupported,
  // Returned by PreCheck
  kMaybeSupported
};

FastCloneObjectMode GetCloneModeForMapPreCheck(DirectHandle<Map> map,
                                               bool null_proto_literal,
                                               Isolate* isolate) {
  DisallowGarbageCollection no_gc;
  if (!IsJSObjectMap(*map)) {
    // Everything that produces the empty object literal can be supported since
    // we have a special case for that.
    if (null_proto_literal) return FastCloneObjectMode::kNotSupported;
    return IsNullOrUndefinedMap(*map) || IsBooleanMap(*map) ||
                   IsHeapNumberMap(*map)
               ? FastCloneObjectMode::kEmptyObject
               : FastCloneObjectMode::kNotSupported;
  }
  ElementsKind elements_kind = map->elements_kind();
  if (!IsSmiOrObjectElementsKind(elements_kind) &&
      !IsAnyNonextensibleElementsKind(elements_kind)) {
    return FastCloneObjectMode::kNotSupported;
  }
  if (!map->OnlyHasSimpleProperties()) {
    return FastCloneObjectMode::kNotSupported;
  }

  // TODO(olivf): Think about cases where cross-context copies are safe.
  if (!map->BelongsToSameNativeContextAs(isolate->context())) {
    return FastCloneObjectMode::kNotSupported;
  }

  return FastCloneObjectMode::kMaybeSupported;
}

FastCloneObjectMode GetCloneModeForMap(DirectHandle<M
"""


```