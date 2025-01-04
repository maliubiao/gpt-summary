Response: Let's break down the thought process for analyzing this C++ code and explaining its function in relation to JavaScript Proxies.

1. **Understand the Context:** The file path `v8/src/builtins/builtins-proxy-gen.cc` immediately tells us this code is part of V8, the JavaScript engine used in Chrome and Node.js. The `builtins` directory suggests it implements built-in JavaScript functionalities. The `-proxy-gen` suffix hints that it's related to the `Proxy` object in JavaScript.

2. **Identify Key Components:**  Scanning the code reveals several important elements:
    * **Includes:**  Standard V8 headers for builtins, code generation (`code-stub-assembler`), objects (especially `JSProxy`), and potentially some Torque-generated code.
    * **Namespace:** `v8::internal` confirms this is internal V8 implementation.
    * **Class:** `ProxiesCodeStubAssembler`. The name strongly suggests this class is responsible for generating code related to Proxy operations. The base class likely provides utilities for generating assembly instructions.
    * **Functions:**  A series of functions like `AllocateProxy`, `CreateProxyRevokeFunctionContext`, `AllocateProxyRevokeFunction`, `TF_BUILTIN(CallProxy, ...)`, `TF_BUILTIN(ConstructProxy, ...)`, and several `Check...TrapResult` functions. The `TF_BUILTIN` macro is a strong indicator of functions directly implementing JavaScript built-in behavior.

3. **Analyze Individual Functions (High-Level):**
    * **`AllocateProxy`:**  Seems responsible for creating a `JSProxy` object in memory. It takes `target` and `handler` as arguments, which are core to the Proxy concept. The logic around `callable_target` and `constructor_target` indicates it handles proxies for both regular functions and constructors.
    * **`CreateProxyRevokeFunctionContext`, `AllocateProxyRevokeFunction`:** These deal with the "revoke" functionality of Proxies. They likely create a special function that, when called, disables the proxy.
    * **`CallProxy`:**  This is clearly invoked when a proxy is called as a function. It handles the core logic of invoking the "apply" trap on the handler. The code checks for a revoked handler and calls the target if no "apply" trap is defined.
    * **`ConstructProxy`:** Similarly, this is invoked when a proxy is used with `new`. It handles the "construct" trap and includes checks for the return type.
    * **`CheckGetSetTrapResult`, `CheckHasTrapResult`, `CheckDeleteTrapResult`:** These functions are about enforcing the invariants of proxies. They check the results of the trap methods ("get", "set", "has", "deleteProperty") against the properties of the target object to ensure the traps are behaving correctly and not violating fundamental object properties (like non-configurable properties).

4. **Connect to JavaScript Proxy Semantics:**  At this point, the relationship to JavaScript `Proxy` becomes clear. The C++ code is implementing the underlying mechanics of how JavaScript `Proxy` objects behave. Each function maps to a specific operation or trap associated with Proxies.

5. **Illustrate with JavaScript Examples:**  The key is to provide simple, concrete JavaScript examples that demonstrate the functionality implemented in the C++ code.

    * **`AllocateProxy`:**  The `new Proxy(target, handler)` syntax directly corresponds to the allocation of the `JSProxy` object. The example should show a basic Proxy creation.
    * **`CallProxy`:**  Calling a proxy directly (e.g., `proxy()`) triggers the "apply" trap. The example needs a proxy with an "apply" handler.
    * **`ConstructProxy`:**  Using `new` with a proxy (e.g., `new proxy()`) triggers the "construct" trap. The example should include a "construct" handler.
    * **`Check...TrapResult`:** These are more subtle but crucial for proxy correctness. Examples need to show scenarios where a trap might return an invalid value, leading to a `TypeError`. For instance, a "get" trap returning a different value for a non-configurable, non-writable property, or a "has" trap returning `false` for a non-configurable property.

6. **Summarize the Functionality:**  Combine the observations into a concise summary explaining that the C++ code implements the core logic of JavaScript Proxies, including allocation, trap handling, and invariant enforcement.

7. **Refine and Structure:** Organize the explanation clearly, starting with a general summary, then delving into the details of each function, and finally providing the JavaScript examples. Use clear and concise language. Highlight the connection between the C++ functions and the corresponding JavaScript behavior.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This looks complex."  **Correction:** Break it down into smaller, manageable parts (the individual functions).
* **Potential confusion:**  The `CodeStubAssembler`. **Clarification:** Recognize it's a V8 mechanism for generating optimized code for built-in functions. The details of how it works aren't as important as understanding *what* it's doing (implementing Proxy behavior).
* **Ensuring the JavaScript examples are accurate:** Double-check the JavaScript Proxy syntax and the expected behavior of each trap. Focus on demonstrating the specific functionality of the C++ code being discussed.
* **Making the connection explicit:** Clearly state how each C++ function relates to a JavaScript concept or operation. Don't just describe the C++ code in isolation.

By following these steps, the analysis becomes structured, and the explanation effectively bridges the gap between the low-level C++ implementation and the high-level JavaScript `Proxy` API.
这个 C++ 源代码文件 `builtins-proxy-gen.cc` 是 V8 JavaScript 引擎中专门用于实现 **JavaScript Proxy 对象**相关功能的代码。它使用 V8 的 CodeStubAssembler (CSA) 框架来生成高效的机器码，用于处理 Proxy 对象的各种操作。

**主要功能归纳:**

1. **Proxy 对象的创建和初始化:**
   - `AllocateProxy`:  负责在内存中分配 `JSProxy` 对象，并初始化其内部属性，如 `target` (被代理的对象) 和 `handler` (包含拦截器函数的对象)。
   - 它会根据 `target` 是否可调用或可构造来设置不同的内部 Map，这决定了 Proxy 对象是否可以像函数或构造函数一样被调用。

2. **Proxy 的撤销 (Revocation):**
   - `CreateProxyRevokeFunctionContext`: 创建一个特殊的上下文，用于存储与 Proxy 撤销函数相关的信息。
   - `AllocateProxyRevokeFunction`: 分配一个内置的函数，当调用该函数时，会撤销与之关联的 Proxy 对象 (即将其 handler 设置为 null，使其失效)。

3. **Proxy 的调用 (Function Calls):**
   - `TF_BUILTIN(CallProxy, ProxiesCodeStubAssembler)`:  这是当一个 Proxy 对象被当作函数调用时执行的内置函数。
   - 它首先检查 Proxy 的 handler 是否已被撤销。
   - 然后，它尝试获取 handler 上的 `apply` 方法 (trap)。
   - 如果 `apply` 方法存在，则调用该方法，并将 target 对象、调用时的 `this` 值和参数列表传递给它。
   - 如果 `apply` 方法不存在，则直接调用 target 对象。

4. **Proxy 的构造 (Constructor Calls):**
   - `TF_BUILTIN(ConstructProxy, ProxiesCodeStubAssembler)`: 这是当一个 Proxy 对象被用作构造函数时执行的内置函数。
   - 类似 `CallProxy`，它也检查 handler 是否被撤销，并尝试获取 handler 上的 `construct` 方法 (trap)。
   - 如果 `construct` 方法存在，则调用它，并将 target 对象、构造函数的参数列表和 `new.target` 传递给它。
   - 如果 `construct` 方法不存在，则调用 target 对象作为构造函数。
   - 它还会检查 `construct` trap 的返回值是否为对象。

5. **Proxy Trap 结果的校验:**
   - `CheckGetSetTrapResult`, `CheckHasTrapResult`, `CheckDeleteTrapResult`: 这些函数负责校验 Proxy 的各种 trap 方法 (如 `get`, `set`, `has`, `deleteProperty`) 的返回值是否符合规范，以确保不会违反 JavaScript 对象的一些基本约束 (invariants)。
   - 例如，如果目标对象的一个属性是不可配置的，那么 Proxy 的 `get` trap 返回的值必须与目标对象的属性值相同。

**与 JavaScript 功能的关系及示例:**

这个文件直接实现了 JavaScript `Proxy` 对象的底层行为。JavaScript 代码中对 `Proxy` 对象的各种操作，最终都会调用到这里定义的 C++ 代码。

**JavaScript 示例:**

```javascript
// 创建一个 Proxy 对象
const target = {
  name: '原始对象',
  age: 30
};

const handler = {
  get(target, prop, receiver) {
    console.log(`访问属性: ${prop}`);
    if (prop === 'age') {
      return target[prop] + 10; // 修改 age 属性的返回值
    }
    return Reflect.get(target, prop, receiver);
  },
  set(target, prop, value, receiver) {
    console.log(`设置属性: ${prop} 为 ${value}`);
    if (prop === 'age' && value < 0) {
      throw new Error("年龄不能为负数");
    }
    return Reflect.set(target, prop, value, receiver);
  },
  apply(target, thisArg, args) {
    console.log("Proxy 对象被调用");
    return target.apply(thisArg, args);
  },
  construct(target, args, newTarget) {
    console.log("Proxy 对象被用作构造函数");
    return new target(...args);
  }
};

const proxy = new Proxy(target, handler);

// 访问 Proxy 对象的属性，触发 handler.get
console.log(proxy.name); // 输出: 访问属性: name, 原始对象
console.log(proxy.age);  // 输出: 访问属性: age, 40

// 设置 Proxy 对象的属性，触发 handler.set
proxy.age = 25;        // 输出: 设置属性: age 为 25

// 尝试设置非法值，触发 handler.set 中的错误
// proxy.age = -5; // 会抛出 Error: 年龄不能为负数

// 如果 target 是一个函数，Proxy 可以拦截函数调用
const fnTarget = function(x) { return x * 2; };
const fnProxy = new Proxy(fnTarget, handler);
console.log(fnProxy(5)); // 输出: Proxy 对象被调用, 10

// 如果 target 是一个构造函数，Proxy 可以拦截 new 操作
class MyClass {
  constructor(value) {
    this.value = value;
  }
}
const classProxy = new Proxy(MyClass, handler);
const instance = new classProxy(10); // 输出: Proxy 对象被用作构造函数
console.log(instance.value); // 输出: 10

// 撤销 Proxy 对象
const revocableProxy = Proxy.revocable(target, handler);
const proxyToRevoke = revocableProxy.proxy;
const revoke = revocableProxy.revoke;

console.log(proxyToRevoke.name);
revoke(); // 撤销 Proxy
// console.log(proxyToRevoke.name); // 报错: Cannot perform 'get' on a proxy that has been revoked
```

**总结:**

`builtins-proxy-gen.cc` 文件是 V8 引擎中实现 JavaScript `Proxy` 核心功能的关键部分。它负责 Proxy 对象的创建、撤销以及各种操作的拦截和处理，并确保这些操作符合 JavaScript 规范。通过 CodeStubAssembler，它生成高效的机器码来提升 Proxy 对象的性能。JavaScript 代码中的 `Proxy` API 的所有行为，都可以在这个 C++ 文件中找到对应的底层实现。

Prompt: 
```
这是目录为v8/src/builtins/builtins-proxy-gen.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/builtins/builtins-proxy-gen.h"

#include "src/builtins/builtins-inl.h"
#include "src/builtins/builtins-utils-gen.h"
#include "src/builtins/builtins-utils.h"
#include "src/codegen/code-stub-assembler-inl.h"
#include "src/common/globals.h"
#include "src/logging/counters.h"
#include "src/objects/js-proxy.h"
#include "src/objects/objects-inl.h"
#include "torque-generated/exported-macros-assembler.h"

namespace v8 {
namespace internal {

#include "src/codegen/define-code-stub-assembler-macros.inc"

TNode<JSProxy> ProxiesCodeStubAssembler::AllocateProxy(
    TNode<Context> context, TNode<JSReceiver> target,
    TNode<JSReceiver> handler) {
  TVARIABLE(Map, map);

  Label callable_target(this), constructor_target(this), none_target(this),
      create_proxy(this);

  TNode<NativeContext> nativeContext = LoadNativeContext(context);

  Branch(IsCallable(target), &callable_target, &none_target);

  BIND(&callable_target);
  {
    // Every object that is a constructor is implicitly callable
    // so it's okay to nest this check here
    GotoIf(IsConstructor(target), &constructor_target);
    map = CAST(
        LoadContextElement(nativeContext, Context::PROXY_CALLABLE_MAP_INDEX));
    Goto(&create_proxy);
  }
  BIND(&constructor_target);
  {
    map = CAST(LoadContextElement(nativeContext,
                                  Context::PROXY_CONSTRUCTOR_MAP_INDEX));
    Goto(&create_proxy);
  }
  BIND(&none_target);
  {
    map = CAST(LoadContextElement(nativeContext, Context::PROXY_MAP_INDEX));
    Goto(&create_proxy);
  }

  BIND(&create_proxy);
  TNode<HeapObject> proxy = Allocate(JSProxy::kSize);
  StoreMapNoWriteBarrier(proxy, map.value());
  RootIndex empty_dict = V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL
                             ? RootIndex::kEmptySwissPropertyDictionary
                             : RootIndex::kEmptyPropertyDictionary;
  StoreObjectFieldRoot(proxy, JSProxy::kPropertiesOrHashOffset, empty_dict);
  StoreObjectFieldNoWriteBarrier(proxy, JSProxy::kTargetOffset, target);
  StoreObjectFieldNoWriteBarrier(proxy, JSProxy::kHandlerOffset, handler);

  return CAST(proxy);
}

TNode<Context> ProxiesCodeStubAssembler::CreateProxyRevokeFunctionContext(
    TNode<JSProxy> proxy, TNode<NativeContext> native_context) {
  const TNode<Context> context = AllocateSyntheticFunctionContext(
      native_context, ProxyRevokeFunctionContextSlot::kProxyContextLength);
  StoreContextElementNoWriteBarrier(
      context, ProxyRevokeFunctionContextSlot::kProxySlot, proxy);
  return context;
}

TNode<JSFunction> ProxiesCodeStubAssembler::AllocateProxyRevokeFunction(
    TNode<Context> context, TNode<JSProxy> proxy) {
  const TNode<NativeContext> native_context = LoadNativeContext(context);
  const TNode<Context> proxy_context =
      CreateProxyRevokeFunctionContext(proxy, native_context);
  return AllocateRootFunctionWithContext(RootIndex::kProxyRevokeSharedFun,
                                         proxy_context, native_context);
}

TF_BUILTIN(CallProxy, ProxiesCodeStubAssembler) {
  auto argc = UncheckedParameter<Int32T>(Descriptor::kActualArgumentsCount);
  TNode<IntPtrT> argc_ptr = ChangeInt32ToIntPtr(argc);
  auto proxy = Parameter<JSProxy>(Descriptor::kFunction);
  auto context = Parameter<Context>(Descriptor::kContext);

  CSA_DCHECK(this, IsCallable(proxy));

  PerformStackCheck(context);

  Label throw_proxy_handler_revoked(this, Label::kDeferred),
      trap_undefined(this);

  // 1. Let handler be the value of the [[ProxyHandler]] internal slot of O.
  TNode<HeapObject> handler =
      CAST(LoadObjectField(proxy, JSProxy::kHandlerOffset));

  // 2. If handler is null, throw a TypeError exception.
  CSA_DCHECK(this, IsNullOrJSReceiver(handler));
  GotoIfNot(JSAnyIsNotPrimitive(handler), &throw_proxy_handler_revoked);

  // 3. Assert: Type(handler) is Object.
  CSA_DCHECK(this, IsJSReceiver(handler));

  // 4. Let target be the value of the [[ProxyTarget]] internal slot of O.
  TNode<Object> target = LoadObjectField(proxy, JSProxy::kTargetOffset);

  // 5. Let trap be ? GetMethod(handler, "apply").
  // 6. If trap is undefined, then
  Handle<Name> trap_name = factory()->apply_string();
  TNode<Object> trap = GetMethod(context, handler, trap_name, &trap_undefined);

  CodeStubArguments args(this, argc_ptr);
  TNode<Object> receiver = args.GetReceiver();

  // 7. Let argArray be CreateArrayFromList(argumentsList).
  TNode<JSArray> array = EmitFastNewAllArguments(
      UncheckedCast<Context>(context),
      UncheckedCast<RawPtrT>(LoadFramePointer()),
      UncheckedCast<IntPtrT>(args.GetLengthWithoutReceiver()));

  // 8. Return Call(trap, handler, «target, thisArgument, argArray»).
  TNode<Object> result = Call(context, trap, handler, target, receiver, array);
  args.PopAndReturn(result);

  BIND(&trap_undefined);
  {
    // 6.a. Return Call(target, thisArgument, argumentsList).
    TailCallBuiltin(Builtins::Call(), context, target, argc);
  }

  BIND(&throw_proxy_handler_revoked);
  { ThrowTypeError(context, MessageTemplate::kProxyRevoked, "apply"); }
}

TF_BUILTIN(ConstructProxy, ProxiesCodeStubAssembler) {
  auto argc = UncheckedParameter<Int32T>(Descriptor::kActualArgumentsCount);
  TNode<IntPtrT> argc_ptr = ChangeInt32ToIntPtr(argc);
  auto proxy = Parameter<JSProxy>(Descriptor::kTarget);
  auto new_target = Parameter<Object>(Descriptor::kNewTarget);
  auto context = Parameter<Context>(Descriptor::kContext);

  CSA_DCHECK(this, IsCallable(proxy));

  PerformStackCheck(context);

  Label throw_proxy_handler_revoked(this, Label::kDeferred),
      trap_undefined(this), not_an_object(this, Label::kDeferred);

  // 1. Let handler be the value of the [[ProxyHandler]] internal slot of O.
  TNode<HeapObject> handler =
      CAST(LoadObjectField(proxy, JSProxy::kHandlerOffset));

  // 2. If handler is null, throw a TypeError exception.
  CSA_DCHECK(this, IsNullOrJSReceiver(handler));
  GotoIfNot(JSAnyIsNotPrimitive(handler), &throw_proxy_handler_revoked);

  // 3. Assert: Type(handler) is Object.
  CSA_DCHECK(this, IsJSReceiver(handler));

  // 4. Let target be the value of the [[ProxyTarget]] internal slot of O.
  TNode<Object> target = LoadObjectField(proxy, JSProxy::kTargetOffset);

  // 5. Let trap be ? GetMethod(handler, "construct").
  // 6. If trap is undefined, then
  Handle<Name> trap_name = factory()->construct_string();
  TNode<Object> trap = GetMethod(context, handler, trap_name, &trap_undefined);

  CodeStubArguments args(this, argc_ptr);

  // 7. Let argArray be CreateArrayFromList(argumentsList).
  TNode<JSArray> array = EmitFastNewAllArguments(
      UncheckedCast<Context>(context),
      UncheckedCast<RawPtrT>(LoadFramePointer()),
      UncheckedCast<IntPtrT>(args.GetLengthWithoutReceiver()));

  // 8. Let newObj be ? Call(trap, handler, « target, argArray, newTarget »).
  TNode<Object> new_obj =
      Call(context, trap, handler, target, array, new_target);

  // 9. If Type(newObj) is not Object, throw a TypeError exception.
  GotoIf(TaggedIsSmi(new_obj), &not_an_object);
  GotoIfNot(JSAnyIsNotPrimitive(CAST(new_obj)), &not_an_object);

  // 10. Return newObj.
  args.PopAndReturn(new_obj);

  BIND(&not_an_object);
  {
    ThrowTypeError(context, MessageTemplate::kProxyConstructNonObject, new_obj);
  }

  BIND(&trap_undefined);
  {
    // 6.a. Assert: target has a [[Construct]] internal method.
    CSA_DCHECK(this, IsConstructor(CAST(target)));

    // 6.b. Return ? Construct(target, argumentsList, newTarget).
    TailCallBuiltin(Builtin::kConstruct, context, target, new_target, argc);
  }

  BIND(&throw_proxy_handler_revoked);
  { ThrowTypeError(context, MessageTemplate::kProxyRevoked, "construct"); }
}

void ProxiesCodeStubAssembler::CheckGetSetTrapResult(
    TNode<Context> context, TNode<JSReceiver> target, TNode<JSProxy> proxy,
    TNode<Name> name, TNode<Object> trap_result,
    JSProxy::AccessKind access_kind) {
  // TODO(mslekova): Think of a better name for the trap_result param.
  TNode<Map> map = LoadMap(target);
  TVARIABLE(Object, var_value);
  TVARIABLE(Uint32T, var_details);
  TVARIABLE(Object, var_raw_value);

  Label if_found_value(this), check_in_runtime(this, Label::kDeferred),
      check_passed(this);

  GotoIfNot(IsUniqueNameNoIndex(name), &check_in_runtime);
  TNode<Uint16T> instance_type = LoadInstanceType(target);
  TryGetOwnProperty(context, target, target, map, instance_type, name,
                    &if_found_value, &var_value, &var_details, &var_raw_value,
                    &check_passed, &check_in_runtime, kReturnAccessorPair);

  BIND(&if_found_value);
  {
    Label throw_non_configurable_data(this, Label::kDeferred),
        throw_non_configurable_accessor(this, Label::kDeferred),
        check_accessor(this), check_data(this);

    // If targetDesc is not undefined and targetDesc.[[Configurable]] is
    // false, then:
    GotoIfNot(IsSetWord32(var_details.value(),
                          PropertyDetails::kAttributesDontDeleteMask),
              &check_passed);

    // If IsDataDescriptor(targetDesc) is true and
    // targetDesc.[[Writable]] is false, then:
    BranchIfAccessorPair(var_raw_value.value(), &check_accessor, &check_data);

    BIND(&check_data);
    {
      TNode<BoolT> read_only = IsSetWord32(
          var_details.value(), PropertyDetails::kAttributesReadOnlyMask);
      GotoIfNot(read_only, &check_passed);

      // If SameValue(trapResult, targetDesc.[[Value]]) is false,
      // throw a TypeError exception.
      BranchIfSameValue(trap_result, var_value.value(), &check_passed,
                        &throw_non_configurable_data);
    }

    BIND(&check_accessor);
    {
      TNode<HeapObject> accessor_pair = CAST(var_raw_value.value());

      if (access_kind == JSProxy::kGet) {
        Label continue_check(this, Label::kDeferred);
        // 10.b. If IsAccessorDescriptor(targetDesc) is true and
        // targetDesc.[[Get]] is undefined, then:
        TNode<Object> getter =
            LoadObjectField(accessor_pair, AccessorPair::kGetterOffset);
        // Here we check for null as well because if the getter was never
        // defined it's set as null.
        GotoIf(IsUndefined(getter), &continue_check);
        GotoIf(IsNull(getter), &continue_check);
        Goto(&check_passed);

        // 10.b.i. If trapResult is not undefined, throw a TypeError exception.
        BIND(&continue_check);
        GotoIfNot(IsUndefined(trap_result), &throw_non_configurable_accessor);
      } else {
        // 11.b.i. If targetDesc.[[Set]] is undefined, throw a TypeError
        // exception.
        TNode<Object> setter =
            LoadObjectField(accessor_pair, AccessorPair::kSetterOffset);
        GotoIf(IsUndefined(setter), &throw_non_configurable_accessor);
        GotoIf(IsNull(setter), &throw_non_configurable_accessor);
      }
      Goto(&check_passed);
    }

    BIND(&throw_non_configurable_data);
    {
      if (access_kind == JSProxy::kGet) {
        ThrowTypeError(context, MessageTemplate::kProxyGetNonConfigurableData,
                       name, var_value.value(), trap_result);
      } else {
        ThrowTypeError(context, MessageTemplate::kProxySetFrozenData, name);
      }
    }

    BIND(&throw_non_configurable_accessor);
    {
      if (access_kind == JSProxy::kGet) {
        ThrowTypeError(context,
                       MessageTemplate::kProxyGetNonConfigurableAccessor, name,
                       trap_result);
      } else {
        ThrowTypeError(context, MessageTemplate::kProxySetFrozenAccessor, name);
      }
    }

    BIND(&check_in_runtime);
    {
      CallRuntime(Runtime::kCheckProxyGetSetTrapResult, context, name, target,
                  trap_result, SmiConstant(access_kind));
      Goto(&check_passed);
    }

    BIND(&check_passed);
  }
}

void ProxiesCodeStubAssembler::CheckHasTrapResult(TNode<Context> context,
                                                  TNode<JSReceiver> target,
                                                  TNode<JSProxy> proxy,
                                                  TNode<Name> name) {
  TNode<Map> target_map = LoadMap(target);
  TVARIABLE(Object, var_value);
  TVARIABLE(Uint32T, var_details);
  TVARIABLE(Object, var_raw_value);

  Label if_found_value(this, Label::kDeferred),
      throw_non_configurable(this, Label::kDeferred),
      throw_non_extensible(this, Label::kDeferred), check_passed(this),
      check_in_runtime(this, Label::kDeferred);

  // 9.a. Let targetDesc be ? target.[[GetOwnProperty]](P).
  GotoIfNot(IsUniqueNameNoIndex(name), &check_in_runtime);
  TNode<Uint16T> instance_type = LoadInstanceType(target);
  TryGetOwnProperty(context, target, target, target_map, instance_type, name,
                    &if_found_value, &var_value, &var_details, &var_raw_value,
                    &check_passed, &check_in_runtime, kReturnAccessorPair);

  // 9.b. If targetDesc is not undefined, then (see 9.b.i. below).
  BIND(&if_found_value);
  {
    // 9.b.i. If targetDesc.[[Configurable]] is false, throw a TypeError
    // exception.
    TNode<BoolT> non_configurable = IsSetWord32(
        var_details.value(), PropertyDetails::kAttributesDontDeleteMask);
    GotoIf(non_configurable, &throw_non_configurable);

    // 9.b.ii. Let extensibleTarget be ? IsExtensible(target).
    TNode<BoolT> target_extensible = IsExtensibleMap(target_map);

    // 9.b.iii. If extensibleTarget is false, throw a TypeError exception.
    GotoIfNot(target_extensible, &throw_non_extensible);
    Goto(&check_passed);
  }

  BIND(&throw_non_configurable);
  { ThrowTypeError(context, MessageTemplate::kProxyHasNonConfigurable, name); }

  BIND(&throw_non_extensible);
  { ThrowTypeError(context, MessageTemplate::kProxyHasNonExtensible, name); }

  BIND(&check_in_runtime);
  {
    CallRuntime(Runtime::kCheckProxyHasTrapResult, context, name, target);
    Goto(&check_passed);
  }

  BIND(&check_passed);
}

void ProxiesCodeStubAssembler::CheckDeleteTrapResult(TNode<Context> context,
                                                     TNode<JSReceiver> target,
                                                     TNode<JSProxy> proxy,
                                                     TNode<Name> name) {
  TNode<Map> target_map = LoadMap(target);
  TVARIABLE(Object, var_value);
  TVARIABLE(Uint32T, var_details);
  TVARIABLE(Object, var_raw_value);

  Label if_found_value(this, Label::kDeferred),
      throw_non_configurable(this, Label::kDeferred),
      throw_non_extensible(this, Label::kDeferred), check_passed(this),
      check_in_runtime(this, Label::kDeferred);

  // 10. Let targetDesc be ? target.[[GetOwnProperty]](P).
  GotoIfNot(IsUniqueNameNoIndex(name), &check_in_runtime);
  TNode<Uint16T> instance_type = LoadInstanceType(target);
  TryGetOwnProperty(context, target, target, target_map, instance_type, name,
                    &if_found_value, &var_value, &var_details, &var_raw_value,
                    &check_passed, &check_in_runtime, kReturnAccessorPair);

  // 11. If targetDesc is undefined, return true.
  BIND(&if_found_value);
  {
    // 12. If targetDesc.[[Configurable]] is false, throw a TypeError exception.
    TNode<BoolT> non_configurable = IsSetWord32(
        var_details.value(), PropertyDetails::kAttributesDontDeleteMask);
    GotoIf(non_configurable, &throw_non_configurable);

    // 13. Let extensibleTarget be ? IsExtensible(target).
    TNode<BoolT> target_extensible = IsExtensibleMap(target_map);

    // 14. If extensibleTarget is false, throw a TypeError exception.
    GotoIfNot(target_extensible, &throw_non_extensible);
    Goto(&check_passed);
  }

  BIND(&throw_non_configurable);
  {
    ThrowTypeError(context,
                   MessageTemplate::kProxyDeletePropertyNonConfigurable, name);
  }

  BIND(&throw_non_extensible);
  {
    ThrowTypeError(context, MessageTemplate::kProxyDeletePropertyNonExtensible,
                   name);
  }

  BIND(&check_in_runtime);
  {
    CallRuntime(Runtime::kCheckProxyDeleteTrapResult, context, name, target);
    Goto(&check_passed);
  }

  BIND(&check_passed);
}

#include "src/codegen/undef-code-stub-assembler-macros.inc"

}  // namespace internal
}  // namespace v8

"""

```