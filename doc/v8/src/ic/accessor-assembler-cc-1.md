Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/ic/accessor-assembler.cc`.

Here's a plan to address the request:

1. **Identify the core purpose of the code:** The code seems to implement various handlers for property access (load and store) in V8's IC (Inline Cache) system. It deals with different property types and access scenarios.
2. **Break down the code into functional blocks:**  The code uses labels and `BIND` to define different execution paths based on handler types and property characteristics. Group these paths to understand the logic.
3. **List the supported handler types:** Identify the different `LOAD_KIND` and `STORE_KIND` constants being checked, like `kField`, `kConstantFromPrototype`, `kAccessor`, `kGlobal`, `kProxy`, `kInterceptor`, etc.
4. **Describe the actions taken in each block:**  Summarize what the code does for each handler type, e.g., loading from a dictionary, calling a getter/setter, handling proxies, interceptors, etc.
5. **Connect to JavaScript functionality:**  Relate the different handler types to how property access works in JavaScript (e.g., accessing a regular property, accessing a getter/setter, accessing a global variable).
6. **Illustrate with JavaScript examples:** Provide simple JavaScript code snippets that would trigger the different code paths in the C++ code.
7. **Identify potential programming errors:**  Look for cases where incorrect JavaScript code might lead to the "miss" labels in the C++ code, which usually indicates a cache miss or an unexpected property access scenario.
8. **Address the `.tq` aspect:** Confirm that this `.cc` file is *not* a Torque file.
9. **Summarize the overall functionality:**  Provide a concise summary based on the above points.
这是对 `v8/src/ic/accessor-assembler.cc` 代码片段的功能归纳，重点关注其处理属性加载和存储的逻辑。

**功能归纳：**

这段代码主要负责处理 JavaScript 对象的属性访问（读取 - Load 和写入 - Store）操作的各种情况。它实现了 V8 引擎中内联缓存 (IC - Inline Cache) 系统的核心部分，针对不同的属性类型和访问模式，优化属性访问的性能。

**具体功能点：**

1. **处理不同类型的 LoadHandler:** 代码通过检查 `handler_kind` 来区分不同的属性加载处理器类型，并采取相应的操作：
    * **快速属性加载 (kField, kConstantFromPrototype):**  直接从对象的已知位置加载属性值。
    * **原型链上的属性 (kAccessorFromPrototype, kNativeDataProperty, kApiGetter):**  在原型链上查找属性，并处理访问器属性（getter）或本地数据属性。
    * **慢速属性 (kNormal):**  当属性存储在对象的慢速属性字典中时进行查找和加载。
    * **全局对象属性 (kGlobal):**  处理全局对象的属性访问。
    * **代理对象属性 (kProxy):**  将属性访问委托给代理对象的处理逻辑。
    * **拦截器属性 (kInterceptor):**  调用运行时函数来处理带有拦截器的属性访问。
    * **模块导出 (kModuleExport):**  处理 ES 模块的导出属性访问。
    * **装箱 Double 值 (rebox_double):**  将 double 类型的数值装箱为 HeapNumber 对象。

2. **处理不同类型的 StoreHandler:** 代码通过检查 `handler_kind` 来区分不同的属性存储处理器类型，并采取相应的操作：
    * **快速属性存储 (kSharedStructField):**  直接存储到共享结构体的字段中。
    * **原生数据属性存储 (kNativeDataProperty):** 调用运行时函数来处理回调属性的存储。
    * **慢速属性存储 (kNormal):** 将属性存储到对象的慢速属性字典中。
    * **代理对象存储 (kProxy):**  将属性存储委托给代理对象的处理逻辑。
    * **拦截器属性存储 (kInterceptor):** 调用运行时函数来处理带有拦截器的属性存储。
    * **全局对象属性存储:** 处理全局对象的属性存储。
    * **属性过渡 (Transition):**  处理对象形状发生变化时的属性存储。
    * **访问器属性存储:** 调用属性的 setter 方法。

3. **原型链处理 (HandleProtoHandler, HandleLoadICProtoHandler, HandleStoreICProtoHandler):**  检查原型链的有效性，并根据原型链上的处理器类型执行相应的加载或存储操作。

4. **访问检查 (EmitAccessCheck):**  对于某些类型的属性访问，需要进行访问权限检查，例如跨上下文的访问。

5. **类型检查 (CheckFieldType):**  在存储操作中，可能需要检查要存储的值是否符合属性的类型。

6. **字典查找 (NameDictionaryLookup):**  在处理慢速属性时，需要在属性字典中查找属性。

7. **调用 Getter/Setter (CallGetterIfAccessor):**  当访问的属性是一个访问器时，需要调用其对应的 getter 或 setter 函数。

8. **处理 Smi 处理器:** 对于一些简单的属性访问场景，可以使用 Smi (Small Integer) 来编码处理器信息，提高性能。

**关于 `.tq` 后缀：**

`v8/src/ic/accessor-assembler.cc` 文件以 `.cc` 结尾，因此**它是一个 C++ 源代码文件，而不是 v8 Torque 源代码**。Torque 源代码文件通常以 `.tq` 结尾。

**与 JavaScript 功能的关系及示例：**

这段 C++ 代码直接支撑着 JavaScript 中属性的读取和写入操作。以下是一些 JavaScript 示例，它们可能会触发代码片段中不同的处理逻辑：

* **普通属性访问 (对应 `load_normal`, `has_normal`, `HandleStoreICSmiHandlerCase`):**
  ```javascript
  const obj = { x: 10 };
  console.log(obj.x); // Load
  obj.x = 20;         // Store
  'x' in obj;         // HasProperty
  ```

* **原型链上的属性访问 (对应 `accessor_load`, `native_data_property`, `api_getter`):**
  ```javascript
  class Parent {
    get y() { return this._y; }
    set y(value) { this._y = value; }
  }
  class Child extends Parent {}
  const child = new Child();
  child.y = 30; // Store (可能触发原型链上的 setter)
  console.log(child.y); // Load (可能触发原型链上的 getter)
  ```

* **全局对象属性访问 (对应 `global`):**
  ```javascript
  globalThis.z = 40; // Store
  console.log(z);      // Load
  'z' in globalThis;
  ```

* **代理对象属性访问 (对应 `proxy`):**
  ```javascript
  const proxy = new Proxy({}, {
    get(target, prop) {
      console.log('Getting ' + prop);
      return target[prop];
    },
    set(target, prop, value) {
      console.log('Setting ' + prop + ' to ' + value);
      target[prop] = value;
      return true;
    }
  });
  proxy.a = 50; // Store
  console.log(proxy.a); // Load
  'a' in proxy;
  ```

* **带有拦截器的属性访问 (对应 `load_interceptor`, `store_interceptor`):**  (这种场景在用户代码中不太常见，通常由 V8 内部或宿主环境使用)

* **模块导出属性访问 (对应 `module_export`):**
  ```javascript
  // module.js
  export const message = 'Hello';

  // main.js
  import { message } from './module.js';
  console.log(message);
  ```

**代码逻辑推理示例：**

**假设输入：**

* `p->name()`: 一个字符串 "count"
* `holder`: 一个普通的 JavaScript 对象 `{ count: 5 }`
* `handler_kind`: `LOAD_KIND(kNormal)`

**输出：**

代码会进入 `BIND(&normal)` 分支。

1. 加载 `holder` 的慢速属性字典。
2. 在字典中查找键为 "count" 的条目。
3. 如果找到，加载对应的值（5）。
4. 调用 `exit_point->Return(value)` 返回值 5。

**用户常见的编程错误示例：**

* **读取未定义的属性:**
  ```javascript
  const obj = {};
  console.log(obj.nonExistent); // 会导致在原型链上查找，最终可能返回 undefined
  ```
  在 C++ 代码中，这可能会导致进入不同的 `LOAD_KIND` 分支，例如 `kNonExistent` 或在原型链上继续查找。

* **在只读属性上赋值:**
  ```javascript
  const obj = {};
  Object.defineProperty(obj, 'readonly', { value: 10, writable: false });
  obj.readonly = 20; // 严格模式下会报错，非严格模式下赋值无效
  ```
  在 C++ 代码中，处理存储操作时会检查属性的 `readonly` 标志，可能会导致 `miss` 或抛出错误。

* **尝试访问代理对象上不存在的属性，且代理没有处理 `get` 陷阱:**
  ```javascript
  const proxy = new Proxy({}, {});
  console.log(proxy.missing); // 如果 Proxy 没有定义 get 陷阱，会直接返回 undefined
  ```
  C++ 代码中会进入 `proxy` 分支，最终调用 `Builtin::kProxyGetProperty`。

**总结：**

这段 `accessor-assembler.cc` 代码片段是 V8 引擎中负责高效处理 JavaScript 对象属性访问的核心组件。它通过区分不同的属性类型和访问模式，利用内联缓存技术优化属性的读取和写入性能，是 V8 引擎实现高性能 JavaScript 执行的关键部分。

### 提示词
```
这是目录为v8/src/ic/accessor-assembler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/ic/accessor-assembler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
ant_load");
    exit_point->Return(holder);
  }

  BIND(&normal);
  {
    Comment("load_normal");
    TNode<PropertyDictionary> properties =
        CAST(LoadSlowProperties(CAST(holder)));
    TVARIABLE(IntPtrT, var_name_index);
    Label found(this, &var_name_index);
    NameDictionaryLookup<PropertyDictionary>(properties, CAST(p->name()),
                                             &found, &var_name_index, miss);
    BIND(&found);
    {
      TVARIABLE(Uint32T, var_details);
      TVARIABLE(Object, var_value);
      LoadPropertyFromDictionary<PropertyDictionary>(
          properties, var_name_index.value(), &var_details, &var_value);
      TNode<Object> value = CallGetterIfAccessor(
          var_value.value(), CAST(holder), var_details.value(), p->context(),
          p->receiver(), p->name(), miss);
      exit_point->Return(value);
    }
  }

  BIND(&accessor);
  {
    Comment("accessor_load");
    // The "holder" slot (data1) in the from-prototype LoadHandler is instead
    // directly the getter function.
    TNode<HeapObject> getter = CAST(holder);
    CSA_DCHECK(this, IsCallable(getter));

    exit_point->Return(Call(p->context(), getter, p->receiver()));
  }

  BIND(&native_data_property);
  HandleLoadCallbackProperty(p, CAST(holder), handler_word, exit_point);

  BIND(&api_getter);
  {
    if (p->receiver() != p->lookup_start_object()) {
      // Force super ICs using API getters into the slow path, so that we get
      // the correct receiver checks.
      Goto(&slow);
    } else {
      HandleLoadAccessor(p, CAST(holder), handler_word, CAST(handler),
                         handler_kind, exit_point);
    }
  }

  BIND(&proxy);
  {
    // TODO(mythria): LoadGlobals don't use this path. LoadGlobals need special
    // handling with proxies which is currently not supported by builtins. So
    // for such cases, we should install a slow path and never reach here. Fix
    // it to not generate this for LoadGlobals.
    CSA_DCHECK(this,
               WordNotEqual(IntPtrConstant(static_cast<int>(on_nonexistent)),
                            IntPtrConstant(static_cast<int>(
                                OnNonExistent::kThrowReferenceError))));
    TVARIABLE(IntPtrT, var_index);
    TVARIABLE(Name, var_unique);

    Label if_index(this), if_unique_name(this),
        to_name_failed(this, Label::kDeferred);

    if (support_elements == kSupportElements) {
      DCHECK_NE(on_nonexistent, OnNonExistent::kThrowReferenceError);

      TryToName(p->name(), &if_index, &var_index, &if_unique_name, &var_unique,
                &to_name_failed);

      BIND(&if_unique_name);
      exit_point->ReturnCallBuiltin(Builtin::kProxyGetProperty, p->context(),
                                    holder, var_unique.value(), p->receiver(),
                                    SmiConstant(on_nonexistent));

      BIND(&if_index);
      // TODO(mslekova): introduce TryToName that doesn't try to compute
      // the intptr index value
      Goto(&to_name_failed);

      BIND(&to_name_failed);
      // TODO(duongn): use GetPropertyWithReceiver builtin once
      // |lookup_element_in_holder| supports elements.
      exit_point->ReturnCallRuntime(Runtime::kGetPropertyWithReceiver,
                                    p->context(), holder, p->name(),
                                    p->receiver(), SmiConstant(on_nonexistent));
    } else {
      exit_point->ReturnCallBuiltin(Builtin::kProxyGetProperty, p->context(),
                                    holder, p->name(), p->receiver(),
                                    SmiConstant(on_nonexistent));
    }
  }

  BIND(&global);
  {
    CSA_DCHECK(this, IsPropertyCell(CAST(holder)));
    // Ensure the property cell doesn't contain the hole.
    TNode<Object> value =
        LoadObjectField(CAST(holder), PropertyCell::kValueOffset);
    TNode<Uint32T> details = Unsigned(LoadAndUntagToWord32ObjectField(
        CAST(holder), PropertyCell::kPropertyDetailsRawOffset));
    GotoIf(IsPropertyCellHole(value), miss);

    exit_point->Return(CallGetterIfAccessor(value, CAST(holder), details,
                                            p->context(), p->receiver(),
                                            p->name(), miss));
  }

  BIND(&interceptor);
  {
    Comment("load_interceptor");
    exit_point->ReturnCallRuntime(Runtime::kLoadPropertyWithInterceptor,
                                  p->context(), p->name(), p->receiver(),
                                  holder, p->slot(), p->vector());
  }
  BIND(&slow);
  {
    Comment("load_slow");
    if (ic_mode == ICMode::kGlobalIC) {
      exit_point->ReturnCallRuntime(Runtime::kLoadGlobalIC_Slow, p->context(),
                                    p->name(), p->slot(), p->vector());

    } else {
      exit_point->ReturnCallRuntime(Runtime::kGetProperty, p->context(),
                                    p->lookup_start_object(), p->name(),
                                    p->receiver());
    }
  }

  BIND(&module_export);
  {
    Comment("module export");
    TNode<UintPtrT> index =
        DecodeWordFromWord32<LoadHandler::ExportsIndexBits>(handler_word);
    TNode<Module> module =
        LoadObjectField<Module>(CAST(holder), JSModuleNamespace::kModuleOffset);
    TNode<ObjectHashTable> exports =
        LoadObjectField<ObjectHashTable>(module, Module::kExportsOffset);
    TNode<Cell> cell = CAST(LoadFixedArrayElement(exports, index));
    // The handler is only installed for exports that exist.
    TNode<Object> value = LoadCellValue(cell);
    Label is_the_hole(this, Label::kDeferred);
    GotoIf(IsTheHole(value), &is_the_hole);
    exit_point->Return(value);

    BIND(&is_the_hole);
    {
      TNode<Smi> message = SmiConstant(MessageTemplate::kNotDefined);
      exit_point->ReturnCallRuntime(Runtime::kThrowReferenceError, p->context(),
                                    message, p->name());
    }
  }

  BIND(rebox_double);
  exit_point->Return(AllocateHeapNumberWithValue(var_double_value->value()));
}

void AccessorAssembler::HandleLoadICSmiHandlerHasNamedCase(
    const LazyLoadICParameters* p, TNode<Object> holder,
    TNode<Uint32T> handler_kind, Label* miss, ExitPoint* exit_point,
    ICMode ic_mode) {
  Label return_true(this), return_false(this), return_lookup(this),
      normal(this), global(this), slow(this);

  GotoIf(Word32Equal(handler_kind, LOAD_KIND(kField)), &return_true);

  GotoIf(Word32Equal(handler_kind, LOAD_KIND(kConstantFromPrototype)),
         &return_true);

  GotoIf(Word32Equal(handler_kind, LOAD_KIND(kNonExistent)), &return_false);

  GotoIf(Word32Equal(handler_kind, LOAD_KIND(kNormal)), &normal);

  GotoIf(Word32Equal(handler_kind, LOAD_KIND(kAccessorFromPrototype)),
         &return_true);

  GotoIf(Word32Equal(handler_kind, LOAD_KIND(kNativeDataProperty)),
         &return_true);

  GotoIf(Word32Equal(handler_kind, LOAD_KIND(kApiGetter)), &return_true);

  GotoIf(Word32Equal(handler_kind, LOAD_KIND(kApiGetterHolderIsPrototype)),
         &return_true);

  GotoIf(Word32Equal(handler_kind, LOAD_KIND(kSlow)), &slow);

  Branch(Word32Equal(handler_kind, LOAD_KIND(kGlobal)), &global,
         &return_lookup);

  BIND(&return_true);
  exit_point->Return(TrueConstant());

  BIND(&return_false);
  exit_point->Return(FalseConstant());

  BIND(&return_lookup);
  {
    CSA_DCHECK(this,
               Word32Or(Word32Equal(handler_kind, LOAD_KIND(kInterceptor)),
                        Word32Or(Word32Equal(handler_kind, LOAD_KIND(kProxy)),
                                 Word32Equal(handler_kind,
                                             LOAD_KIND(kModuleExport)))));
    exit_point->ReturnCallBuiltin(Builtin::kHasProperty, p->context(),
                                  p->receiver(), p->name());
  }

  BIND(&normal);
  {
    Comment("has_normal");
    TNode<PropertyDictionary> properties =
        CAST(LoadSlowProperties(CAST(holder)));
    TVARIABLE(IntPtrT, var_name_index);
    Label found(this);
    NameDictionaryLookup<PropertyDictionary>(properties, CAST(p->name()),
                                             &found, &var_name_index, miss);

    BIND(&found);
    exit_point->Return(TrueConstant());
  }

  BIND(&global);
  {
    CSA_DCHECK(this, IsPropertyCell(CAST(holder)));
    // Ensure the property cell doesn't contain the hole.
    TNode<Object> value =
        LoadObjectField(CAST(holder), PropertyCell::kValueOffset);
    GotoIf(IsPropertyCellHole(value), miss);

    exit_point->Return(TrueConstant());
  }

  BIND(&slow);
  {
    Comment("load_slow");
    if (ic_mode == ICMode::kGlobalIC) {
      exit_point->ReturnCallRuntime(Runtime::kLoadGlobalIC_Slow, p->context(),
                                    p->name(), p->slot(), p->vector());
    } else {
      exit_point->ReturnCallRuntime(Runtime::kHasProperty, p->context(),
                                    p->receiver(), p->name());
    }
  }
}

// Performs actions common to both load and store handlers:
// 1. Checks prototype validity cell.
// 2. If |on_code_handler| is provided, then it checks if the sub handler is
//    a smi or code and if it's a code then it calls |on_code_handler| to
//    generate a code that handles Code handlers.
//    If |on_code_handler| is not provided, then only smi sub handler are
//    expected.
// 3. Does access check on lookup start object if
//    ICHandler::DoAccessCheckOnLookupStartObjectBits bit is set in the smi
//    handler.
// 4. Does dictionary lookup on receiver if
//    ICHandler::LookupOnLookupStartObjectBits bit is set in the smi handler. If
//    |on_found_on_lookup_start_object| is provided then it calls it to
//    generate a code that handles the "found on receiver case" or just misses
//    if the |on_found_on_lookup_start_object| is not provided.
// 5. Falls through in a case of a smi handler which is returned from this
//    function (tagged!).
// TODO(ishell): Remove templatezation once we move common bits from
// Load/StoreHandler to the base class.
template <typename ICHandler, typename ICParameters>
TNode<Object> AccessorAssembler::HandleProtoHandler(
    const ICParameters* p, TNode<DataHandler> handler,
    const OnCodeHandler& on_code_handler,
    const OnFoundOnLookupStartObject& on_found_on_lookup_start_object,
    Label* miss, ICMode ic_mode) {
  //
  // Check prototype validity cell.
  //
  {
    TNode<Object> maybe_validity_cell =
        LoadObjectField(handler, ICHandler::kValidityCellOffset);
    CheckPrototypeValidityCell(maybe_validity_cell, miss);
  }

  //
  // Check smi handler bits.
  //
  {
    TNode<Object> smi_or_code_handler =
        LoadObjectField(handler, ICHandler::kSmiHandlerOffset);
    if (on_code_handler) {
      Label if_smi_handler(this);
      GotoIf(TaggedIsSmi(smi_or_code_handler), &if_smi_handler);
      TNode<Code> code = CAST(smi_or_code_handler);
      on_code_handler(code);

      BIND(&if_smi_handler);
    }
    TNode<IntPtrT> handler_flags = SmiUntag(CAST(smi_or_code_handler));

    // Lookup on receiver and access checks are not necessary for global ICs
    // because in the former case the validity cell check guards modifications
    // of the global object and the latter is not applicable to the global
    // object.
    int mask = ICHandler::LookupOnLookupStartObjectBits::kMask |
               ICHandler::DoAccessCheckOnLookupStartObjectBits::kMask;
    if (ic_mode == ICMode::kGlobalIC) {
      CSA_DCHECK(this, IsClearWord(handler_flags, mask));
    } else {
      DCHECK_EQ(ICMode::kNonGlobalIC, ic_mode);

      Label done(this), if_do_access_check(this),
          if_lookup_on_lookup_start_object(this);
      GotoIf(IsClearWord(handler_flags, mask), &done);
      // Only one of the bits can be set at a time.
      CSA_DCHECK(this,
                 WordNotEqual(WordAnd(handler_flags, IntPtrConstant(mask)),
                              IntPtrConstant(mask)));
      Branch(
          IsSetWord<typename ICHandler::DoAccessCheckOnLookupStartObjectBits>(
              handler_flags),
          &if_do_access_check, &if_lookup_on_lookup_start_object);

      BIND(&if_do_access_check);
      {
        TNode<MaybeObject> data2 = LoadHandlerDataField(handler, 2);
        CSA_DCHECK(this, IsWeakOrCleared(data2));
        TNode<Context> expected_native_context =
            CAST(GetHeapObjectAssumeWeak(data2, miss));
        EmitAccessCheck(expected_native_context, p->context(),
                        p->lookup_start_object(), &done, miss);
      }

      BIND(&if_lookup_on_lookup_start_object);
      {
        // Dictionary lookup on lookup start object is not necessary for
        // Load/StoreGlobalIC (which is the only case when the
        // lookup_start_object can be a JSGlobalObject) because prototype
        // validity cell check already guards modifications of the global
        // object.
        CSA_DCHECK(this,
                   Word32BinaryNot(HasInstanceType(
                       CAST(p->lookup_start_object()), JS_GLOBAL_OBJECT_TYPE)));

        TNode<PropertyDictionary> properties =
            CAST(LoadSlowProperties(CAST(p->lookup_start_object())));
        TVARIABLE(IntPtrT, var_name_index);
        Label found(this, &var_name_index);
        NameDictionaryLookup<PropertyDictionary>(
            properties, CAST(p->name()), &found, &var_name_index, &done);
        BIND(&found);
        {
          if (on_found_on_lookup_start_object) {
            on_found_on_lookup_start_object(properties, var_name_index.value());
          } else {
            Goto(miss);
          }
        }
      }

      BIND(&done);
    }
    return smi_or_code_handler;
  }
}

void AccessorAssembler::HandleLoadICProtoHandler(
    const LazyLoadICParameters* p, TNode<DataHandler> handler,
    TVariable<Object>* var_holder, TVariable<MaybeObject>* var_smi_handler,
    Label* if_smi_handler, Label* miss, ExitPoint* exit_point, ICMode ic_mode,
    LoadAccessMode access_mode) {
  TNode<Smi> smi_handler = CAST(HandleProtoHandler<LoadHandler>(
      p, handler,
      // Code sub-handlers are not expected in LoadICs, so no |on_code_handler|.
      nullptr,
      // on_found_on_lookup_start_object
      [=, this](TNode<PropertyDictionary> properties,
                TNode<IntPtrT> name_index) {
        if (access_mode == LoadAccessMode::kHas) {
          exit_point->Return(TrueConstant());
        } else {
          TVARIABLE(Uint32T, var_details);
          TVARIABLE(Object, var_value);
          LoadPropertyFromDictionary<PropertyDictionary>(
              properties, name_index, &var_details, &var_value);
          TNode<Object> value = CallGetterIfAccessor(
              var_value.value(), CAST(var_holder->value()), var_details.value(),
              p->context(), p->receiver(), p->name(), miss);
          exit_point->Return(value);
        }
      },
      miss, ic_mode));

  TNode<MaybeObject> maybe_holder_or_constant =
      LoadHandlerDataField(handler, 1);

  Label load_from_cached_holder(this), is_smi(this), done(this);

  GotoIf(TaggedIsSmi(maybe_holder_or_constant), &is_smi);
  Branch(TaggedEqual(maybe_holder_or_constant, NullConstant()), &done,
         &load_from_cached_holder);

  BIND(&is_smi);
  {
    // If the "maybe_holder_or_constant" in the handler is a smi, then it's
    // guaranteed that it's not a holder object, but a constant value.
    CSA_DCHECK(this, Word32Equal(DecodeWord32<LoadHandler::KindBits>(
                                     SmiToInt32(smi_handler)),
                                 LOAD_KIND(kConstantFromPrototype)));
    if (access_mode == LoadAccessMode::kHas) {
      exit_point->Return(TrueConstant());
    } else {
      exit_point->Return(CAST(maybe_holder_or_constant));
    }
  }

  BIND(&load_from_cached_holder);
  {
    // For regular holders, having passed the receiver map check and
    // the validity cell check implies that |holder| is
    // alive. However, for global object receivers, |maybe_holder| may
    // be cleared.
    CSA_DCHECK(this, IsWeakOrCleared(maybe_holder_or_constant));
    TNode<HeapObject> holder =
        GetHeapObjectAssumeWeak(maybe_holder_or_constant, miss);
    *var_holder = holder;
    Goto(&done);
  }

  BIND(&done);
  {
    *var_smi_handler = smi_handler;
    Goto(if_smi_handler);
  }
}

void AccessorAssembler::EmitAccessCheck(TNode<Context> expected_native_context,
                                        TNode<Context> context,
                                        TNode<Object> receiver,
                                        Label* can_access, Label* miss) {
  CSA_DCHECK(this, IsNativeContext(expected_native_context));

  TNode<NativeContext> native_context = LoadNativeContext(context);
  GotoIf(TaggedEqual(expected_native_context, native_context), can_access);
  // If the receiver is not a JSGlobalProxy then we miss.
  GotoIf(TaggedIsSmi(receiver), miss);
  GotoIfNot(IsJSGlobalProxy(CAST(receiver)), miss);
  // For JSGlobalProxy receiver try to compare security tokens of current
  // and expected native contexts.
  TNode<Object> expected_token = LoadContextElement(
      expected_native_context, Context::SECURITY_TOKEN_INDEX);
  TNode<Object> current_token =
      LoadContextElement(native_context, Context::SECURITY_TOKEN_INDEX);
  Branch(TaggedEqual(expected_token, current_token), can_access, miss);
}

void AccessorAssembler::JumpIfDataProperty(TNode<Uint32T> details,
                                           Label* writable, Label* readonly) {
  if (readonly) {
    // Accessor properties never have the READ_ONLY attribute set.
    GotoIf(IsSetWord32(details, PropertyDetails::kAttributesReadOnlyMask),
           readonly);
  } else {
    CSA_DCHECK(this, IsNotSetWord32(details,
                                    PropertyDetails::kAttributesReadOnlyMask));
  }
  TNode<Uint32T> kind = DecodeWord32<PropertyDetails::KindField>(details);
  GotoIf(
      Word32Equal(kind, Int32Constant(static_cast<int>(PropertyKind::kData))),
      writable);
  // Fall through if it's an accessor property.
}

void AccessorAssembler::HandleStoreICNativeDataProperty(
    const StoreICParameters* p, TNode<HeapObject> holder,
    TNode<Word32T> handler_word) {
  Comment("native_data_property_store");
  TNode<IntPtrT> descriptor =
      Signed(DecodeWordFromWord32<StoreHandler::DescriptorBits>(handler_word));
  TNode<AccessorInfo> accessor_info =
      CAST(LoadDescriptorValue(LoadMap(holder), descriptor));

  TailCallRuntime(Runtime::kStoreCallbackProperty, p->context(), p->receiver(),
                  holder, accessor_info, p->name(), p->value());
}

void AccessorAssembler::HandleStoreICSmiHandlerJSSharedStructFieldCase(
    TNode<Context> context, TNode<Word32T> handler_word, TNode<JSObject> holder,
    TNode<Object> value) {
  CSA_DCHECK(this,
             Word32Equal(DecodeWord32<StoreHandler::KindBits>(handler_word),
                         STORE_KIND(kSharedStructField)));
  CSA_DCHECK(
      this,
      Word32Equal(DecodeWord32<StoreHandler::RepresentationBits>(handler_word),
                  Int32Constant(Representation::kTagged)));

  TVARIABLE(Object, shared_value, value);
  SharedValueBarrier(context, &shared_value);

  TNode<BoolT> is_inobject =
      IsSetWord32<StoreHandler::IsInobjectBits>(handler_word);
  TNode<HeapObject> property_storage = Select<HeapObject>(
      is_inobject, [&]() { return holder; },
      [&]() { return LoadFastProperties(holder, true); });

  TNode<UintPtrT> index =
      DecodeWordFromWord32<StoreHandler::FieldIndexBits>(handler_word);
  TNode<IntPtrT> offset = Signed(TimesTaggedSize(index));

  StoreSharedObjectField(property_storage, offset, shared_value.value());

  // Return the original value.
  Return(value);
}

void AccessorAssembler::HandleStoreICHandlerCase(
    const StoreICParameters* p, TNode<MaybeObject> handler, Label* miss,
    ICMode ic_mode, ElementSupport support_elements) {
  Label if_smi_handler(this), if_nonsmi_handler(this);
  Label if_proto_handler(this), call_handler(this),
      store_transition_or_global_or_accessor(this);

  Branch(TaggedIsSmi(handler), &if_smi_handler, &if_nonsmi_handler);

  Label if_slow(this);

  // |handler| is a Smi, encoding what to do. See SmiHandler methods
  // for the encoding format.
  BIND(&if_smi_handler);
  {
    TNode<Object> holder = p->receiver();
    TNode<Int32T> handler_word = SmiToInt32(CAST(handler));

    Label if_fast_smi(this), if_proxy(this), if_interceptor(this);

#define ASSERT_CONSECUTIVE(a, b)                                    \
  static_assert(static_cast<intptr_t>(StoreHandler::Kind::a) + 1 == \
                static_cast<intptr_t>(StoreHandler::Kind::b));
    ASSERT_CONSECUTIVE(kGlobalProxy, kNormal)
    ASSERT_CONSECUTIVE(kNormal, kInterceptor)
    ASSERT_CONSECUTIVE(kInterceptor, kSlow)
    ASSERT_CONSECUTIVE(kSlow, kProxy)
    ASSERT_CONSECUTIVE(kProxy, kKindsNumber)
#undef ASSERT_CONSECUTIVE

    TNode<Uint32T> handler_kind =
        DecodeWord32<StoreHandler::KindBits>(handler_word);
    GotoIf(Int32LessThan(handler_kind, STORE_KIND(kGlobalProxy)), &if_fast_smi);
    GotoIf(Word32Equal(handler_kind, STORE_KIND(kProxy)), &if_proxy);
    GotoIf(Word32Equal(handler_kind, STORE_KIND(kInterceptor)),
           &if_interceptor);
    GotoIf(Word32Equal(handler_kind, STORE_KIND(kSlow)), &if_slow);
    CSA_DCHECK(this, Word32Equal(handler_kind, STORE_KIND(kNormal)));
    TNode<PropertyDictionary> properties =
        CAST(LoadSlowProperties(CAST(holder)));

    TVARIABLE(IntPtrT, var_name_index);
    Label dictionary_found(this, &var_name_index);
    if (p->IsAnyDefineOwn()) {
      NameDictionaryLookup<PropertyDictionary>(properties, CAST(p->name()),
                                               &if_slow, nullptr, miss);
    } else {
      NameDictionaryLookup<PropertyDictionary>(properties, CAST(p->name()),
                                               &dictionary_found,
                                               &var_name_index, miss);
    }

    // When dealing with class fields defined with DefineKeyedOwnIC or
    // DefineNamedOwnIC, use the slow path to check the existing property.
    if (!p->IsAnyDefineOwn()) {
      BIND(&dictionary_found);
      {
        Label if_constant(this), done(this);
        TNode<Uint32T> details =
            LoadDetailsByKeyIndex(properties, var_name_index.value());
        // Check that the property is a writable data property (no accessor).
        const int kTypeAndReadOnlyMask =
            PropertyDetails::KindField::kMask |
            PropertyDetails::kAttributesReadOnlyMask;
        static_assert(static_cast<int>(PropertyKind::kData) == 0);
        GotoIf(IsSetWord32(details, kTypeAndReadOnlyMask), miss);

        if (V8_DICT_PROPERTY_CONST_TRACKING_BOOL) {
          GotoIf(IsPropertyDetailsConst(details), miss);
        }

        StoreValueByKeyIndex<PropertyDictionary>(
            properties, var_name_index.value(), p->value());
        Return(p->value());
      }
    }
    BIND(&if_fast_smi);
    {
      Label data(this), shared_struct_field(this), native_data_property(this);
      GotoIf(Word32Equal(handler_kind, STORE_KIND(kNativeDataProperty)),
             &native_data_property);
      Branch(Word32Equal(handler_kind, STORE_KIND(kSharedStructField)),
             &shared_struct_field, &data);

      BIND(&native_data_property);
      HandleStoreICNativeDataProperty(p, CAST(holder), handler_word);

      BIND(&shared_struct_field);
      HandleStoreICSmiHandlerJSSharedStructFieldCase(p->context(), handler_word,
                                                     CAST(holder), p->value());

      BIND(&data);
      // Handle non-transitioning field stores.
      HandleStoreICSmiHandlerCase(handler_word, CAST(holder), p->value(), miss);
    }

    BIND(&if_proxy);
    {
      CSA_DCHECK(this, BoolConstant(!p->IsDefineKeyedOwn()));
      HandleStoreToProxy(p, CAST(holder), miss, support_elements);
    }

    BIND(&if_interceptor);
    {
      Comment("store_interceptor");
      TailCallRuntime(Runtime::kStorePropertyWithInterceptor, p->context(),
                      p->value(), p->receiver(), p->name());
    }

    BIND(&if_slow);
    {
      Comment("store_slow");
      // The slow case calls into the runtime to complete the store without
      // causing an IC miss that would otherwise cause a transition to the
      // generic stub.
      if (ic_mode == ICMode::kGlobalIC) {
        TailCallRuntime(Runtime::kStoreGlobalIC_Slow, p->context(), p->value(),
                        p->slot(), p->vector(), p->receiver(), p->name());
      } else {
        Runtime::FunctionId id;
        if (p->IsDefineNamedOwn()) {
          id = Runtime::kDefineNamedOwnIC_Slow;
        } else if (p->IsDefineKeyedOwn()) {
          id = Runtime::kDefineKeyedOwnIC_Slow;
        } else {
          id = Runtime::kKeyedStoreIC_Slow;
        }
        TailCallRuntime(id, p->context(), p->value(), p->receiver(), p->name());
      }
    }
  }

  BIND(&if_nonsmi_handler);
  {
    TNode<HeapObjectReference> ref_handler = CAST(handler);
    GotoIf(IsWeakOrCleared(ref_handler),
           &store_transition_or_global_or_accessor);
    TNode<HeapObject> strong_handler = CAST(handler);
    TNode<Map> handler_map = LoadMap(strong_handler);
    Branch(IsCodeMap(handler_map), &call_handler, &if_proto_handler);

    BIND(&if_proto_handler);
    {
      // Note, although DefineOwnICs don't reqiure checking for prototype
      // chain modifications the proto handlers shape is still used for
      // StoreHandler::StoreElementTransition in order to store both Code
      // handler and transition target map.
      HandleStoreICProtoHandler(p, CAST(strong_handler), &if_slow, miss,
                                ic_mode, support_elements);
    }

    // |handler| is a heap object. Must be code, call it.
    BIND(&call_handler);
    {
      TNode<Code> code_handler = CAST(strong_handler);
      TailCallStub(StoreWithVectorDescriptor{}, code_handler, p->context(),
                   p->receiver(), p->name(), p->value(), p->slot(),
                   p->vector());
    }
  }

  BIND(&store_transition_or_global_or_accessor);
  {
    // Load value or miss if the {handler} weak cell is cleared.
    CSA_DCHECK(this, IsWeakOrCleared(handler));
    TNode<HeapObject> strong_handler = GetHeapObjectAssumeWeak(handler, miss);

    Label store_global(this), store_transition(this), store_accessor(this);
    TNode<Map> strong_handler_map = LoadMap(strong_handler);
    GotoIf(IsPropertyCellMap(strong_handler_map), &store_global);
    Branch(IsAccessorPairMap(strong_handler_map), &store_accessor,
           &store_transition);

    BIND(&store_global);
    {
      if (p->IsDefineKeyedOwn()) {
        Label proceed_defining(this);
        // StoreGlobalIC_PropertyCellCase doesn't support definition
        // of private fields, so handle them in runtime.
        GotoIfNot(IsSymbol(CAST(p->name())), &proceed_defining);
        Branch(IsPrivateName(CAST(p->name())), &if_slow, &proceed_defining);
        BIND(&proceed_defining);
      }

      TNode<PropertyCell> property_cell = CAST(strong_handler);
      ExitPoint direct_exit(this);
      StoreGlobalIC_PropertyCellCase(property_cell, p->value(), &direct_exit,
                                     miss);
    }
    BIND(&store_accessor);
    {
      TNode<AccessorPair> pair = CAST(strong_handler);
      TNode<JSFunction> setter = CAST(LoadAccessorPairSetter(pair));
      // As long as this code path is not used for StoreSuperIC the receiver
      // is known to be neither undefined nor null.
      ConvertReceiverMode mode = ConvertReceiverMode::kNotNullOrUndefined;
      Return(
          CallFunction(p->context(), setter, mode, p->receiver(), p->value()));
    }
    BIND(&store_transition);
    {
      TNode<Map> map = CAST(strong_handler);
      HandleStoreICTransitionMapHandlerCase(p, map, miss,
                                            p->IsAnyDefineOwn()
                                                ? kDontCheckPrototypeValidity
                                                : kCheckPrototypeValidity);
      Return(p->value());
    }
  }
}

void AccessorAssembler::HandleStoreICTransitionMapHandlerCase(
    const StoreICParameters* p, TNode<Map> transition_map, Label* miss,
    StoreTransitionMapFlags flags) {
  DCHECK_EQ(0, flags & ~kStoreTransitionMapFlagsMask);
  if (flags & kCheckPrototypeValidity) {
    TNode<Object> maybe_validity_cell =
        LoadObjectField(transition_map, Map::kPrototypeValidityCellOffset);
    CheckPrototypeValidityCell(maybe_validity_cell, miss);
  }

  TNode<Uint32T> bitfield3 = LoadMapBitField3(transition_map);
  CSA_DCHECK(this, IsClearWord32<Map::Bits3::IsDictionaryMapBit>(bitfield3));
  GotoIf(IsSetWord32<Map::Bits3::IsDeprecatedBit>(bitfield3), miss);

  // Load last descriptor details.
  TNode<UintPtrT> nof =
      DecodeWordFromWord32<Map::Bits3::NumberOfOwnDescriptorsBits>(bitfield3);
  CSA_DCHECK(this, WordNotEqual(nof, IntPtrConstant(0)));
  TNode<DescriptorArray> descriptors = LoadMapDescriptors(transition_map);

  TNode<IntPtrT> factor = IntPtrConstant(DescriptorArray::kEntrySize);
  TNode<IntPtrT> last_key_index = UncheckedCast<IntPtrT>(IntPtrAdd(
      IntPtrConstant(DescriptorArray::ToKeyIndex(-1)), IntPtrMul(nof, factor)));
  if (flags & kValidateTransitionHandler) {
    TNode<Name> key = LoadKeyByKeyIndex(descriptors, last_key_index);
    GotoIf(TaggedNotEqual(key, p->name()), miss);
  } else {
    CSA_DCHECK(this, TaggedEqual(LoadKeyByKeyIndex(descriptors, last_key_index),
                                 p->name()));
  }
  TNode<Uint32T> details = LoadDetailsByKeyIndex(descriptors, last_key_index);
  if (flags & kValidateTransitionHandler) {
    // Follow transitions only in the following cases:
    // 1) name is a non-private symbol and attributes equal to NONE,
    // 2) name is a private symbol and attributes equal to DONT_ENUM.
    Label attributes_ok(this);
    const int kKindAndAttributesDontDeleteReadOnlyMask =
        PropertyDetails::KindField::kMask |
        PropertyDetails::kAttributesDontDeleteMask |
        PropertyDetails::kAttributesReadOnlyMask;
    static_assert(static_cast<int>(PropertyKind::kData) == 0);
    // Both DontDelete and ReadOnly attributes must not be set and it has to be
    // a kData property.
    GotoIf(IsSetWord32(details, kKindAndAttributesDontDeleteReadOnlyMask),
           miss);

    // DontEnum attribute is allowed only for private symbols and vice versa.
    Branch(Word32Equal(
               IsSetWord32(details, PropertyDetails::kAttributesDontEnumMask),
               IsPrivateSymbol(CAST(p->name()))),
           &attributes_ok, miss);

    BIND(&attributes_ok);
  }

  OverwriteExistingFastDataProperty(CAST(p->receiver()), transition_map,
                                    descriptors, last_key_index, details,
                                    p->value(), miss, true);
}

void AccessorAssembler::UpdateMayHaveInterestingProperty(
    TNode<PropertyDictionary> dict, TNode<Name> name) {
  Comment("UpdateMayHaveInterestingProperty");
  Label done(this);

  if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
    // TODO(pthier): Add flags to swiss dictionaries.
    Goto(&done);
  } else {
    GotoIfNot(IsInterestingProperty(name), &done);
    TNode<Smi> flags = GetNameDictionaryFlags(dict);
    flags = SmiOr(
        flags,
        SmiConstant(
            NameDictionary::MayHaveInterestingPropertiesBit::encode(true)));
    SetNameDictionaryFlags(dict, flags);
    Goto(&done);
  }
  BIND(&done);
}

void AccessorAssembler::CheckFieldType(TNode<DescriptorArray> descriptors,
                                       TNode<IntPtrT> name_index,
                                       TNode<Word32T> representation,
                                       TNode<Object> value, Label* bailout) {
  Label r_smi(this), r_double(this), r_heapobject(this), all_fine(this);
  GotoIf(Word32Equal(representation, Int32Constant(Representation::kSmi)),
         &r_smi);
  GotoIf(Word32Equal(representation, Int32Constant(Representation::kDouble)),
         &r_double);
  GotoIf(
      Word32Equal(representation, Int32Constant(Representation::kHeapObject)),
      &r_heapobject);
  GotoIf(Word32Equal(representation, Int32Constant(Representation::kNone)),
         bailout);
  CSA_DCHECK(this, Word32Equal(representation,
                               Int32Constant(Representation::kTagged)));
  Goto(&all_fine);

  BIND(&r_smi);
  { Branch(TaggedIsSmi(value), &all_fine, bailout); }

  BIND(&r_double);
  {
    GotoIf(TaggedIsSmi(value), &all_fine);
    Branch(IsHeapNumber(CAST(value)), &all_fine, bailout);
  }

  BIND(&r_heapobject);
  {
    GotoIf(TaggedIsSmi(value), bailout);
    TNode<MaybeObject> field_type =
        LoadFieldTypeByKeyIndex(descriptors, name_index);
    const Address kAnyType
```