Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/ic/keyed-store-generic.cc`.

Here's a breakdown of how to address the request:

1. **Identify Core Functionality:**  The code deals with storing values into JavaScript objects, specifically focusing on the "keyed store" operation (accessing properties using keys, which can be strings or symbols). The "Generic" part likely indicates a fallback or more general implementation used when faster, specialized versions aren't applicable.

2. **Relate to JavaScript:** Think about how property assignment works in JavaScript. `obj[key] = value` is the direct JavaScript equivalent. Consider the different types of keys (strings, symbols, numbers), the different kinds of properties (data properties, accessors), and the prototype chain.

3. **Explain Torque (if applicable):**  Check the `.tq` extension. If it were `.tq`, explain that Torque is V8's domain-specific language for writing assembly-like code within V8.

4. **Illustrate with JavaScript Examples:** Provide simple JavaScript code snippets that demonstrate the scenarios handled by the C++ code (e.g., storing a new property, overwriting an existing one, using accessors).

5. **Infer Code Logic and Input/Output:**  Analyze the control flow (jumps, branches, labels). Hypothesize what inputs (object, key, value, map state) would lead to different execution paths and what the expected outcome (success, failure, call to runtime) would be.

6. **Identify Common Programming Errors:** Think about common mistakes developers make when working with object properties in JavaScript (e.g., trying to write to a read-only property, accidentally modifying a prototype).

7. **Summarize Functionality:** Condense the findings into a concise overview of what the code does.

**Mental Walkthrough of the Code:**

* **`LookupPropertyOnPrototypeChain`:** This function seems to traverse the prototype chain to find a property.
* **`FindCandidateStoreICTransitionMapHandler`:** This looks for potential optimizations (transition maps) for property storage.
* **`EmitGenericPropertyStore`:** This is the core function. It handles different scenarios:
    * **Fast properties:**  Properties stored directly within the object.
    * **Dictionary properties:** Properties stored in a separate dictionary (used when an object has many properties).
    * **Accessors (getters/setters):**  Special methods called when getting or setting a property.
    * **Read-only properties:**  Properties that cannot be changed.
    * **Prototype chain lookups:**  Checking for properties inherited from prototypes.
    * **Stub cache:**  A mechanism for caching and reusing optimized code for property access.
* **`KeyedStoreGeneric`:** This is the main entry point, handling different key types (integer indices, strings/symbols).
* **`StoreProperty`:**  A higher-level function that calls `KeyedStoreGeneric`.

**Constraint Checklist & Confidence Score:**

* 列举一下它的功能: Yes
* 如果v8/src/ic/keyed-store-generic.cc以.tq结尾，那它是个v8 torque源代码: Yes
* 如果它与javascript的功能有关系，请用javascript举例说明: Yes
* 如果有代码逻辑推理，请给出假设输入与输出: Yes
* 如果涉及用户常见的编程错误，请举例说明: Yes
* 这是第2部分，共2部分，请归纳一下它的功能: Yes

Confidence Score: 5/5

Strategizing complete. I will now generate the response based on these steps.
好的，这是v8源代码文件 `v8/src/ic/keyed-store-generic.cc` 的功能归纳：

**功能概述**

`v8/src/ic/keyed-store-generic.cc` 文件实现了 V8 引擎中用于**通用键值存储操作**的核心逻辑。当 JavaScript 代码尝试给对象的属性赋值时（例如 `object[key] = value`），如果 V8 的内联缓存（Inline Cache, IC）未能命中或者需要处理更复杂的情况，就会调用这个文件中的代码。

**详细功能点**

1. **处理不同类型的接收者 (Receiver) 和键 (Key):**
   -  区分接收者是普通对象还是需要特殊处理的对象（例如，具有拦截器、需要访问检查的对象、字符串和字符串包装器、代理对象等）。对于特殊接收者，会跳到慢速路径（通常是调用运行时函数）。
   -  区分键是整数索引还是字符串/Symbol。整数索引会调用元素存储相关的逻辑，字符串/Symbol 会调用属性存储相关的逻辑。
   -  尝试将键转换为规范化的字符串 (internalized string)，以提高后续查找效率。

2. **快速属性存储 (Fast Property Store):**
   -  对于拥有快速属性的对象，它会查找对象的描述符数组 (DescriptorArray) 来确定属性是否存在以及其属性（例如，数据属性还是访问器属性，是否只读）。
   -  如果找到数据属性，且属性可写，则直接更新属性的值。
   -  如果找到访问器属性（setter），则调用 setter 函数。
   -  如果需要进行属性过渡（例如，添加新属性或改变属性类型），则查找合适的过渡映射 (transition map) 并应用过渡。

3. **字典属性存储 (Dictionary Property Store):**
   -  对于使用字典模式存储属性的对象，它会在属性字典 (PropertyDictionary) 中查找键。
   -  如果找到数据属性，且属性可写，则更新属性的值。
   -  如果找到访问器属性（setter），则调用 setter 函数。
   -  如果键不存在，且对象可扩展，则将新的属性添加到字典中。

4. **原型链查找 (Prototype Chain Lookup):**
   -  在存储属性时，如果当前对象上没有找到该属性，它会沿着原型链向上查找。如果在原型链上找到了 setter，则会调用该 setter。

5. **处理访问器属性 (Accessor Properties):**
   -  当尝试给具有 setter 的访问器属性赋值时，会加载 AccessorPair 中的 setter 函数并调用它。
   -  如果 setter 不可调用，则会抛出 `TypeError` 异常（在严格模式下）或静默失败（在非严格模式下）。

6. **处理只读属性 (Read-Only Properties):**
   -  如果尝试给只读属性赋值，会根据是否处于严格模式抛出 `TypeError` 异常或静默失败。

7. **内联缓存 (Inline Cache) 探测:**
   -  在某些情况下（例如，对于 API 对象），会尝试探测存储操作的内联缓存，以期找到之前缓存的处理程序 (handler) 并执行，从而提高性能。

8. **慢速路径 (Slow Path):**
   -  对于无法快速处理的情况，会调用运行时 (Runtime) 函数，例如 `Runtime::kSetKeyedProperty` 或 `Runtime::kDefineObjectOwnProperty`，进行更复杂的处理。

**与 JavaScript 功能的关系和示例**

`v8/src/ic/keyed-store-generic.cc` 中实现的功能直接对应于 JavaScript 中给对象属性赋值的操作。

```javascript
const obj = {};

// 对应快速属性存储，假设 obj 的属性以快速模式存储
obj.name = 'Alice';

// 对应字典属性存储，如果 obj 的属性以字典模式存储
obj['age'] = 30;

const objWithSetter = {
  _value: 0,
  set value(newValue) {
    console.log('Setting value to', newValue);
    this._value = newValue;
  },
  get value() {
    return this._value;
  }
};

// 对应访问器属性的存储
objWithSetter.value = 10; // 会调用 setter

const readOnlyObj = {};
Object.defineProperty(readOnlyObj, 'id', {
  value: 123,
  writable: false
});

// 对应只读属性的尝试赋值，在严格模式下会报错
'use strict';
// readOnlyObj.id = 456; // TypeError: Cannot assign to read only property 'id' of object '#<Object>'

const proto = { protoProp: 'proto value' };
const child = Object.create(proto);

// 对应原型链查找，如果在 child 对象上找不到，会去原型上找 setter
child.protoProp = 'child value'; // 如果 proto 上有 protoProp 的 setter，则会调用它
```

**代码逻辑推理：假设输入与输出**

假设有以下 JavaScript 代码：

```javascript
const myObject = { a: 1 };
myObject.b = 2;
```

**假设输入到 `EmitGenericPropertyStore` 函数:**

* `receiver`:  `myObject` 对应的 V8 对象。
* `receiver_map`: `myObject` 的 Map (描述了对象的结构和类型)。
* `instance_type`:  `myObject` 的实例类型（例如，`JS_OBJECT_TYPE`）。
* `name`:  字符串 "b" 对应的 V8 字符串对象。
* `value`:  数字 2 对应的 V8 数字对象。
* `slow`: 指向慢速路径的 Label。

**可能的代码执行路径和输出：**

1. **检查 `myObject` 的 Map：** 确定 `myObject` 是否以快速属性模式存储属性。
2. **查找描述符:** 如果是快速属性，会在 `myObject` 的描述符数组中查找 "b"。
3. **未找到描述符:** 因为 "b" 是新属性，所以不会在现有的描述符中找到。
4. **查找过渡:**  会尝试查找从 `myObject` 当前的 Map 过渡到包含 "b" 属性的 Map 的过渡映射。
5. **应用过渡:** 如果找到合适的过渡映射，`myObject` 的 Map 会被更新为新的 Map，并且 "b" 属性会被添加到 `myObject` 的快速属性存储区。
6. **写入值:**  值 2 会被写入到 "b" 属性对应的内存位置。
7. **输出:** 函数执行成功，`myObject.b` 的值为 2。

如果 `myObject` 的属性是以字典模式存储的，则会进入 `dictionary_properties` 的逻辑，直接在属性字典中添加 "b" 和对应的值。

**用户常见的编程错误**

1. **尝试给只读属性赋值：**

   ```javascript
   'use strict';
   const obj = {};
   Object.defineProperty(obj, 'constant', { value: 10, writable: false });
   // 错误：TypeError: Cannot assign to read only property 'constant' of object '#<Object>'
   obj.constant = 20;
   ```
   V8 会在 `EmitGenericPropertyStore` 中检测到 `writable: false` 并抛出异常（在严格模式下）。

2. **意外修改了原型对象的属性：**

   ```javascript
   function Parent() { }
   Parent.prototype.name = 'Parent Name';
   const child1 = new Parent();
   const child2 = new Parent();

   // 错误：修改了原型对象的属性，影响了所有子对象
   child1.name = 'Child 1 Name';
   console.log(child2.name); // 输出 "Parent Name"，但如果理解有误，可能期望输出 "Parent Name"

   // 正确的做法是给子对象自身添加属性
   child1.__proto__.name = 'Modified Parent Name'; // 不推荐直接修改 __proto__
   console.log(child2.name); // 输出 "Modified Parent Name"
   ```
   在存储属性时，V8 会首先检查当前对象是否有该属性，如果没有，则会在原型链上查找。如果直接给子对象赋值，会在子对象自身上创建新的属性，而不会修改原型对象的属性（除非原型对象上的属性是 setter）。

3. **在 setter 中没有正确处理赋值：**

   ```javascript
   const obj = {
     _value: 0,
     set value(newValue) {
       console.log('Attempting to set value to', newValue);
       // 错误：忘记更新内部的 _value
       // this._value = newValue;
     },
     get value() {
       return this._value;
     }
   };

   obj.value = 5;
   console.log(obj.value); // 输出 0，因为 setter 没有实际赋值
   ```
   `EmitGenericPropertyStore` 会调用 setter，但 setter 内部的逻辑错误会导致赋值行为不符合预期。

**功能归纳 (作为第 2 部分的总结)**

`v8/src/ic/keyed-store-generic.cc` 是 V8 引擎中处理通用键值存储操作的关键组成部分。它负责处理 JavaScript 中给对象属性赋值的各种情况，包括快速属性和字典属性的存储、原型链的查找、访问器属性的处理以及只读属性的检查。该文件中的代码是 V8 优化属性访问和操作的基础，确保了 JavaScript 代码中属性赋值操作的正确性和性能。当内联缓存未能提供优化路径时，这里的通用逻辑就成为了保障属性赋值操作的关键。

Prompt: 
```
这是目录为v8/src/ic/keyed-store-generic.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/ic/keyed-store-generic.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
), &next_proto);
        TNode<Uint32T> details = Unsigned(LoadAndUntagToWord32ObjectField(
            property_cell, PropertyCell::kPropertyDetailsRawOffset));
        JumpIfDataProperty(details, &ok_to_write, readonly);

        if (accessor != nullptr) {
          // Accessor case.
          *var_accessor_pair = value;
          *var_accessor_holder = holder;
          Goto(accessor);
        } else {
          Goto(&ok_to_write);
        }
      }
    }

    BIND(&next_proto);
    // Bailout if it can be an integer indexed exotic case.
    GotoIf(IsJSTypedArrayInstanceType(instance_type), bailout);
    TNode<HeapObject> proto = LoadMapPrototype(holder_map);
    GotoIf(IsNull(proto), &ok_to_write);
    var_holder = proto;
    var_holder_map = LoadMap(proto);
    Goto(&loop);
  }
  BIND(&ok_to_write);
}

TNode<Map> KeyedStoreGenericAssembler::FindCandidateStoreICTransitionMapHandler(
    TNode<Map> map, TNode<Name> name, Label* slow) {
  TVARIABLE(Map, var_transition_map);
  Label simple_transition(this), transition_array(this),
      found_handler_candidate(this);

  TNode<MaybeObject> maybe_handler =
      LoadMaybeWeakObjectField(map, Map::kTransitionsOrPrototypeInfoOffset);

  // Smi -> slow,
  // Cleared weak reference -> slow
  // weak reference -> simple_transition
  // strong reference -> transition_array
  TVARIABLE(Object, var_transition_map_or_array);
  DispatchMaybeObject(maybe_handler, slow, slow, &simple_transition,
                      &transition_array, &var_transition_map_or_array);

  BIND(&simple_transition);
  {
    var_transition_map = CAST(var_transition_map_or_array.value());
    Goto(&found_handler_candidate);
  }

  BIND(&transition_array);
  {
    TNode<Map> maybe_handler_map =
        LoadMap(CAST(var_transition_map_or_array.value()));
    GotoIfNot(IsTransitionArrayMap(maybe_handler_map), slow);

    TVARIABLE(IntPtrT, var_name_index);
    Label if_found_candidate(this);
    TNode<TransitionArray> transitions =
        CAST(var_transition_map_or_array.value());
    TransitionLookup(name, transitions, &if_found_candidate, &var_name_index,
                     slow);

    BIND(&if_found_candidate);
    {
      // Given that
      // 1) transitions with the same name are ordered in the transition
      //    array by PropertyKind and then by PropertyAttributes values,
      // 2) kData < kAccessor,
      // 3) NONE == 0,
      // 4) properties with private symbol names are guaranteed to be
      //    non-enumerable (so DONT_ENUM bit in attributes is always set),
      // the resulting map of transitioning store if it exists in the
      // transition array is expected to be the first among the transitions
      // with the same name.
      // See TransitionArray::CompareDetails() for details.
      static_assert(static_cast<int>(PropertyKind::kData) == 0);
      static_assert(NONE == 0);
      const int kKeyToTargetOffset = (TransitionArray::kEntryTargetIndex -
                                      TransitionArray::kEntryKeyIndex) *
                                     kTaggedSize;
      var_transition_map = CAST(GetHeapObjectAssumeWeak(
          LoadArrayElement(transitions, OFFSET_OF_DATA_START(WeakFixedArray),
                           var_name_index.value(), kKeyToTargetOffset)));
      Goto(&found_handler_candidate);
    }
  }

  BIND(&found_handler_candidate);
  return var_transition_map.value();
}

void KeyedStoreGenericAssembler::EmitGenericPropertyStore(
    TNode<JSReceiver> receiver, TNode<Map> receiver_map,
    TNode<Uint16T> instance_type, const StoreICParameters* p,
    ExitPoint* exit_point, Label* slow, Maybe<LanguageMode> maybe_language_mode,
    UseStubCache use_stub_cache) {
  CSA_DCHECK(this, IsSimpleObjectMap(receiver_map));
  // TODO(rmcilroy) Type as Struct once we use a trimmed down
  // LoadAccessorFromFastObject instead of LoadPropertyFromFastObject.
  TVARIABLE(Object, var_accessor_pair);
  TVARIABLE(HeapObject, var_accessor_holder);
  Label fast_properties(this), dictionary_properties(this), accessor(this),
      readonly(this), try_stub_cache(this);
  TNode<Uint32T> bitfield3 = LoadMapBitField3(receiver_map);
  TNode<Name> name = CAST(p->name());
  Branch(IsSetWord32<Map::Bits3::IsDictionaryMapBit>(bitfield3),
         &dictionary_properties, &fast_properties);

  BIND(&fast_properties);
  {
    Comment("fast property store");
    TNode<DescriptorArray> descriptors = LoadMapDescriptors(receiver_map);
    Label descriptor_found(this), lookup_transition(this);
    TVARIABLE(IntPtrT, var_name_index);
    DescriptorLookup(name, descriptors, bitfield3,
                     IsAnyDefineOwn() ? slow : &descriptor_found,
                     &var_name_index, &lookup_transition);

    // When dealing with class fields defined with DefineKeyedOwnIC or
    // DefineNamedOwnIC, use the slow path to check the existing property.
    if (!IsAnyDefineOwn()) {
      BIND(&descriptor_found);
      {
        TNode<IntPtrT> name_index = var_name_index.value();
        TNode<Uint32T> details = LoadDetailsByKeyIndex(descriptors, name_index);
        Label data_property(this);
        JumpIfDataProperty(details, &data_property,
                           ShouldReconfigureExisting() ? nullptr : &readonly);

        if (ShouldCallSetter()) {
          // Accessor case.
          // TODO(jkummerow): Implement a trimmed-down
          // LoadAccessorFromFastObject.
          LoadPropertyFromFastObject(receiver, receiver_map, descriptors,
                                     name_index, details, &var_accessor_pair);
          var_accessor_holder = receiver;
          Goto(&accessor);
        } else {
          // Handle accessor to data property reconfiguration in runtime.
          Goto(slow);
        }

        BIND(&data_property);
        {
          Label shared(this);
          GotoIf(IsJSSharedStructInstanceType(instance_type), &shared);

          CheckForAssociatedProtector(name, slow);
          OverwriteExistingFastDataProperty(receiver, receiver_map, descriptors,
                                            name_index, details, p->value(),
                                            slow, false);
          exit_point->Return(p->value());

          BIND(&shared);
          {
            StoreJSSharedStructField(p->context(), receiver, receiver_map,
                                     descriptors, name_index, details,
                                     p->value());
            exit_point->Return(p->value());
          }
        }
      }
    }

    BIND(&lookup_transition);
    {
      Comment("lookup transition");
      CheckForAssociatedProtector(name, slow);

      DCHECK_IMPLIES(use_stub_cache == kUseStubCache, IsSet());
      Label* if_not_found =
          use_stub_cache == kUseStubCache ? &try_stub_cache : slow;

      TNode<Map> transition_map = FindCandidateStoreICTransitionMapHandler(
          receiver_map, name, if_not_found);

      // Validate the transition handler candidate and apply the transition.
      StoreTransitionMapFlags flags = kValidateTransitionHandler;
      if (ShouldCheckPrototypeValidity()) {
        flags = StoreTransitionMapFlags(flags | kCheckPrototypeValidity);
      }
      HandleStoreICTransitionMapHandlerCase(p, transition_map, slow, flags);
      exit_point->Return(p->value());
    }
  }

  BIND(&dictionary_properties);
  {
    Comment("dictionary property store");
    // We checked for LAST_CUSTOM_ELEMENTS_RECEIVER before, which rules out
    // seeing global objects here (which would need special handling).

    TVARIABLE(IntPtrT, var_name_index);
    Label dictionary_found(this, &var_name_index),
        not_found(this, &var_name_index);
    TNode<PropertyDictionary> properties = CAST(LoadSlowProperties(receiver));

    // When dealing with class fields defined with DefineKeyedOwnIC or
    // DefineNamedOwnIC, use the slow path to check the existing property.
    NameDictionaryLookup<PropertyDictionary>(
        properties, name, IsAnyDefineOwn() ? slow : &dictionary_found,
        &var_name_index, &not_found, kFindExistingOrInsertionIndex);

    if (!IsAnyDefineOwn()) {
      BIND(&dictionary_found);
      {
        Label check_const(this), overwrite(this), done(this);
        TNode<Uint32T> details =
            LoadDetailsByKeyIndex(properties, var_name_index.value());
        JumpIfDataProperty(details, &check_const,
                           ShouldReconfigureExisting() ? nullptr : &readonly);

        if (ShouldCallSetter()) {
          // Accessor case.
          var_accessor_pair =
              LoadValueByKeyIndex(properties, var_name_index.value());
          var_accessor_holder = receiver;
          Goto(&accessor);
        } else {
          // We must reconfigure an accessor property to a data property
          // here, let the runtime take care of that.
          Goto(slow);
        }

        BIND(&check_const);
        {
          if (V8_DICT_PROPERTY_CONST_TRACKING_BOOL) {
            GotoIfNot(IsPropertyDetailsConst(details), &overwrite);
            TNode<Object> prev_value =
                LoadValueByKeyIndex(properties, var_name_index.value());

            Branch(TaggedEqual(prev_value, p->value()), &done, slow);
          } else {
            Goto(&overwrite);
          }
        }

        BIND(&overwrite);
        {
          CheckForAssociatedProtector(name, slow);
          StoreValueByKeyIndex<PropertyDictionary>(
              properties, var_name_index.value(), p->value());
          Goto(&done);
        }

        BIND(&done);
        exit_point->Return(p->value());
      }
    }

    BIND(&not_found);
    {
      // TODO(jkummerow): Also add support to correctly handle integer exotic
      // cases for typed arrays and remove this check here.
      GotoIf(IsJSTypedArrayMap(receiver_map), slow);
      CheckForAssociatedProtector(name, slow);
      Label extensible(this), is_private_symbol(this);
      GotoIf(IsPrivateSymbol(name), &is_private_symbol);
      Branch(IsSetWord32<Map::Bits3::IsExtensibleBit>(bitfield3), &extensible,
             slow);

      BIND(&is_private_symbol);
      {
        CSA_DCHECK(this, IsPrivateSymbol(name));
        // For private names, we miss to the runtime which will throw.
        // For private symbols, we extend and store an own property.
        Branch(IsPrivateName(CAST(name)), slow, &extensible);
      }

      BIND(&extensible);
      if (ShouldCheckPrototype()) {
        DCHECK(ShouldCallSetter());
        LookupPropertyOnPrototypeChain(
            receiver_map, name, &accessor, &var_accessor_pair,
            &var_accessor_holder,
            ShouldReconfigureExisting() ? nullptr : &readonly, slow);
      }
      Label add_dictionary_property_slow(this);
      InvalidateValidityCellIfPrototype(receiver_map, bitfield3);
      UpdateMayHaveInterestingProperty(properties, name);
      AddToDictionary<PropertyDictionary>(properties, name, p->value(),
                                          &add_dictionary_property_slow,
                                          var_name_index.value());
      exit_point->Return(p->value());

      BIND(&add_dictionary_property_slow);
      exit_point->ReturnCallRuntime(Runtime::kAddDictionaryProperty,
                                    p->context(), p->receiver(), name,
                                    p->value());
    }
  }

  if (ShouldCallSetter()) {
    BIND(&accessor);
    {
      Label not_callable(this);
      TNode<HeapObject> accessor_pair = CAST(var_accessor_pair.value());
      GotoIf(IsAccessorInfo(accessor_pair), slow);
      CSA_DCHECK(this, IsAccessorPair(accessor_pair));
      TNode<HeapObject> setter =
          CAST(LoadObjectField(accessor_pair, AccessorPair::kSetterOffset));
      TNode<Map> setter_map = LoadMap(setter);
      // FunctionTemplateInfo setters are not supported yet.
      GotoIf(IsFunctionTemplateInfoMap(setter_map), slow);
      GotoIfNot(IsCallableMap(setter_map), &not_callable);

      Call(p->context(), setter, receiver, p->value());
      exit_point->Return(p->value());

      BIND(&not_callable);
      {
        LanguageMode language_mode;
        if (maybe_language_mode.To(&language_mode)) {
          if (language_mode == LanguageMode::kStrict) {
            exit_point->ReturnCallRuntime(
                Runtime::kThrowTypeError, p->context(),
                SmiConstant(MessageTemplate::kNoSetterInCallback), name,
                var_accessor_holder.value());
          } else {
            exit_point->Return(p->value());
          }
        } else {
          CallRuntime(Runtime::kThrowTypeErrorIfStrict, p->context(),
                      SmiConstant(MessageTemplate::kNoSetterInCallback), name,
                      var_accessor_holder.value());
          exit_point->Return(p->value());
        }
      }
    }
  }

  if (!ShouldReconfigureExisting() && !IsAnyDefineOwn()) {
    BIND(&readonly);
    {
      LanguageMode language_mode;
      if (maybe_language_mode.To(&language_mode)) {
        if (language_mode == LanguageMode::kStrict) {
          TNode<String> type = Typeof(p->receiver());
          ThrowTypeError(p->context(), MessageTemplate::kStrictReadOnlyProperty,
                         name, type, p->receiver());
        } else {
          exit_point->Return(p->value());
        }
      } else {
        CallRuntime(Runtime::kThrowTypeErrorIfStrict, p->context(),
                    SmiConstant(MessageTemplate::kStrictReadOnlyProperty), name,
                    Typeof(p->receiver()), p->receiver());
        exit_point->Return(p->value());
      }
    }
  }

  if (use_stub_cache == kUseStubCache) {
    DCHECK(IsSet());
    BIND(&try_stub_cache);
    // Do megamorphic cache lookup only for Api objects where it definitely
    // pays off.
    GotoIfNot(IsJSApiObjectInstanceType(instance_type), slow);

    Comment("stub cache probe");
    TVARIABLE(MaybeObject, var_handler);
    Label found_handler(this, &var_handler), stub_cache_miss(this);

    TryProbeStubCache(p->stub_cache(isolate()), receiver, name, &found_handler,
                      &var_handler, &stub_cache_miss);

    BIND(&found_handler);
    {
      Comment("KeyedStoreGeneric found handler");
      HandleStoreICHandlerCase(p, var_handler.value(), &stub_cache_miss,
                               ICMode::kNonGlobalIC);
    }
    BIND(&stub_cache_miss);
    {
      Comment("KeyedStoreGeneric_miss");
      TailCallRuntime(Runtime::kKeyedStoreIC_Miss, p->context(), p->value(),
                      p->slot(), p->vector(), p->receiver(), name);
    }
  }
}

// Helper that is used by the public KeyedStoreGeneric and by StoreProperty.
void KeyedStoreGenericAssembler::KeyedStoreGeneric(
    TNode<Context> context, TNode<Object> receiver_maybe_smi, TNode<Object> key,
    TNode<Object> value, Maybe<LanguageMode> language_mode,
    UseStubCache use_stub_cache, TNode<TaggedIndex> slot,
    TNode<HeapObject> maybe_vector) {
  DCHECK_IMPLIES(use_stub_cache == kUseStubCache, IsSet());
  TVARIABLE(IntPtrT, var_index);
  TVARIABLE(Name, var_unique);
  Label if_index(this, &var_index), if_unique_name(this),
      not_internalized(this), slow(this);

  GotoIf(TaggedIsSmi(receiver_maybe_smi), &slow);
  TNode<HeapObject> receiver = CAST(receiver_maybe_smi);
  TNode<Map> receiver_map = LoadMap(receiver);
  TNode<Uint16T> instance_type = LoadMapInstanceType(receiver_map);
  // Receivers requiring non-standard element accesses (interceptors, access
  // checks, strings and string wrappers, proxies) are handled in the runtime.
  GotoIf(IsCustomElementsReceiverInstanceType(instance_type), &slow);

  TryToName(key, &if_index, &var_index, &if_unique_name, &var_unique, &slow,
            &not_internalized);

  BIND(&if_index);
  {
    Comment("integer index");
    EmitGenericElementStore(CAST(receiver), receiver_map, instance_type,
                            var_index.value(), value, context, &slow);
  }

  BIND(&if_unique_name);
  {
    Comment("key is unique name");
    StoreICParameters p(context, receiver, var_unique.value(), value,
                        std::nullopt, slot, maybe_vector,
                        StoreICMode::kDefault);
    ExitPoint direct_exit(this);
    EmitGenericPropertyStore(CAST(receiver), receiver_map, instance_type, &p,
                             &direct_exit, &slow, language_mode,
                             use_stub_cache);
  }

  BIND(&not_internalized);
  {
    if (v8_flags.internalize_on_the_fly) {
      TryInternalizeString(CAST(key), &if_index, &var_index, &if_unique_name,
                           &var_unique, &slow, &slow);
    } else {
      Goto(&slow);
    }
  }

  BIND(&slow);
  {
    if (IsSet() || IsDefineNamedOwn()) {
      // The DefineNamedOwnIC hacky reuse should never reach here.
      CSA_DCHECK(this, BoolConstant(!IsDefineNamedOwn()));
      Comment("KeyedStoreGeneric_slow");
      TailCallRuntime(Runtime::kSetKeyedProperty, context, receiver, key,
                      value);
    } else if (IsDefineKeyedOwn()) {
      TailCallRuntime(Runtime::kDefineObjectOwnProperty, context, receiver, key,
                      value);
    } else {
      DCHECK(IsDefineKeyedOwnInLiteral());
      TNode<Smi> flags =
          SmiConstant(DefineKeyedOwnPropertyInLiteralFlag::kNoFlags);
      TNode<TaggedIndex> slot =
          TaggedIndexConstant(FeedbackSlot::Invalid().ToInt());
      TailCallRuntime(Runtime::kDefineKeyedOwnPropertyInLiteral, context,
                      receiver, key, value, flags, UndefinedConstant(), slot);
    }
  }
}

void KeyedStoreGenericAssembler::KeyedStoreGeneric() {
  using Descriptor = StoreNoFeedbackDescriptor;

  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  auto name = Parameter<Object>(Descriptor::kName);
  auto value = Parameter<Object>(Descriptor::kValue);
  auto context = Parameter<Context>(Descriptor::kContext);

  KeyedStoreGeneric(context, receiver, name, value, Nothing<LanguageMode>());
}

void KeyedStoreGenericAssembler::KeyedStoreMegamorphic() {
  DCHECK(IsSet());  // Only [[Set]] handlers are stored in the stub cache.
  using Descriptor = StoreWithVectorDescriptor;

  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  auto name = Parameter<Object>(Descriptor::kName);
  auto value = Parameter<Object>(Descriptor::kValue);
  auto context = Parameter<Context>(Descriptor::kContext);
  auto slot = Parameter<TaggedIndex>(Descriptor::kSlot);
  auto maybe_vector = Parameter<HeapObject>(Descriptor::kVector);

  KeyedStoreGeneric(context, receiver, name, value, Nothing<LanguageMode>(),
                    kUseStubCache, slot, maybe_vector);
}

void KeyedStoreGenericAssembler::StoreProperty(TNode<Context> context,
                                               TNode<Object> receiver,
                                               TNode<Object> key,
                                               TNode<Object> value,
                                               LanguageMode language_mode) {
  KeyedStoreGeneric(context, receiver, key, value, Just(language_mode));
}

void KeyedStoreGenericAssembler::StoreIC_NoFeedback() {
  using Descriptor = StoreNoFeedbackDescriptor;

  auto receiver_maybe_smi = Parameter<Object>(Descriptor::kReceiver);
  auto name = Parameter<Object>(Descriptor::kName);
  auto value = Parameter<Object>(Descriptor::kValue);
  auto context = Parameter<Context>(Descriptor::kContext);

  Label miss(this, Label::kDeferred), store_property(this);

  GotoIf(TaggedIsSmi(receiver_maybe_smi), &miss);

  {
    TNode<HeapObject> receiver = CAST(receiver_maybe_smi);
    TNode<Map> receiver_map = LoadMap(receiver);
    TNode<Uint16T> instance_type = LoadMapInstanceType(receiver_map);
    // Receivers requiring non-standard element accesses (interceptors, access
    // checks, strings and string wrappers, proxies) are handled in the runtime.
    GotoIf(IsSpecialReceiverInstanceType(instance_type), &miss);
    {
      StoreICParameters p(context, receiver, name, value, std::nullopt, {},
                          UndefinedConstant(),
                          IsDefineNamedOwn() ? StoreICMode::kDefineNamedOwn
                                             : StoreICMode::kDefault);
      EmitGenericPropertyStore(CAST(receiver), receiver_map, instance_type, &p,
                               &miss);
    }
  }

  BIND(&miss);
  {
    auto runtime = IsDefineNamedOwn() ? Runtime::kDefineNamedOwnIC_Miss
                                      : Runtime::kStoreIC_Miss;
    TNode<TaggedIndex> slot =
        TaggedIndexConstant(FeedbackSlot::Invalid().ToInt());
    TailCallRuntime(runtime, context, value, slot, UndefinedConstant(),
                    receiver_maybe_smi, name);
  }
}

void KeyedStoreGenericAssembler::StoreProperty(TNode<Context> context,
                                               TNode<JSReceiver> receiver,
                                               TNode<BoolT> is_simple_receiver,
                                               TNode<Name> unique_name,
                                               TNode<Object> value,
                                               LanguageMode language_mode) {
  StoreICParameters p(context, receiver, unique_name, value, std::nullopt, {},
                      UndefinedConstant(), StoreICMode::kDefault);

  Label done(this), slow(this, Label::kDeferred);
  ExitPoint exit_point(this, [&](TNode<Object> result) { Goto(&done); });

  CSA_DCHECK(this, Word32Equal(is_simple_receiver,
                               IsSimpleObjectMap(LoadMap(receiver))));
  GotoIfNot(is_simple_receiver, &slow);

  TNode<Map> map = LoadMap(receiver);
  TNode<Uint16T> instance_type = LoadMapInstanceType(map);
  EmitGenericPropertyStore(receiver, map, instance_type, &p, &exit_point, &slow,
                           Just(language_mode), kDontUseStubCache);

  BIND(&slow);
  {
    if (IsDefineKeyedOwnInLiteral()) {
      TNode<Smi> flags =
          SmiConstant(DefineKeyedOwnPropertyInLiteralFlag::kNoFlags);
      TNode<TaggedIndex> slot =
          TaggedIndexConstant(FeedbackSlot::Invalid().ToInt());
      CallRuntime(Runtime::kDefineKeyedOwnPropertyInLiteral, context, receiver,
                  unique_name, value, flags, p.vector(), slot);
    } else {
      CallRuntime(Runtime::kSetKeyedProperty, context, receiver, unique_name,
                  value);
    }
    Goto(&done);
  }

  BIND(&done);
}

#include "src/codegen/undef-code-stub-assembler-macros.inc"

}  // namespace internal
}  // namespace v8

"""


```