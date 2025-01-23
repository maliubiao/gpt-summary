Response: The user wants a summary of the C++ code in `v8/src/ic/accessor-assembler.cc`. This is the second part of a four-part summary. Therefore, the summary should focus on the code within this specific chunk and build upon any understanding established in the (unseen) first part.

Based on the code provided, the file seems to contain helper functions for generating assembly code related to property access (loading and storing). It uses the CodeStubAssembler (CSA) framework within V8.

Here's a breakdown of the functionality in this specific part:

1. **Type Checking and Field Access:** The `CheckFieldType` function verifies if a value being stored is compatible with the declared type of the field. `OverwriteExistingFastDataProperty` handles updating existing properties, dealing with in-object and backing-store properties, and considering different data representations (tagged, double).

2. **Shared Structs:**  `StoreJSSharedStructField` focuses on storing values in shared structs, ensuring proper handling of shared memory.

3. **Prototype Chain Validation:** `CheckPrototypeValidityCell` checks the validity of a prototype chain.

4. **Store IC Handling:**  The `HandleStoreICProtoHandler` function is a core component for handling property store operations, especially when prototypes are involved. It handles various store handler types (normal, slow, global proxy, accessor, native data property, API setter, proxy).

5. **Proxy Handling:** `HandleStoreToProxy` manages property stores on proxy objects.

6. **Smi Handler for Stores:** `HandleStoreICSmiHandlerCase` is specifically for handling stores when the store handler is a small integer (Smi), often indicating a fast property access. It deals with different field representations (Smi, double, heap object, tagged).

7. **Field Store Logic:** `HandleStoreFieldAndReturn` performs the actual store operation to a field, considering the representation and handling constant fields.

8. **Extending Property Backing Store:** `ExtendPropertiesBackingStore` increases the size of the backing storage for properties when needed.

9. **Element Access (Loading):**  `EmitFastElementsBoundsCheck` and `EmitElementLoad` are crucial for accessing elements in JavaScript objects (arrays and typed arrays). They handle various element kinds (packed, holey, double, typed arrays, dictionaries) and perform bounds checks.

10. **Prototype Invalidation:** `InvalidateValidityCellIfPrototype` invalidates prototype chains when necessary.

11. **Generic Element Load:** `GenericElementLoad` provides a general mechanism for loading elements, falling back to slower paths for complex cases.

12. **Generic Property Load:** `GenericPropertyLoad` handles loading properties in a more general way, including looking up properties in dictionaries and traversing the prototype chain. It also interfaces with the StubCache for optimization.

13. **Stub Cache Interaction:** Several functions (`StubCachePrimaryOffset`, `StubCacheSecondaryOffset`, `TryProbeStubCacheTable`, `TryProbeStubCache`) are dedicated to interacting with the StubCache, a mechanism for optimizing property access by caching frequently used access patterns.

14. **Load IC Entry Points:**  `LoadIC_BytecodeHandler` and `LoadIC` are entry points for handling property load operations triggered from bytecode. They implement fast paths (monomorphic and polymorphic lookups) and fallbacks to more general mechanisms. `LoadSuperIC` is similar but specifically for `super` property access.

15. **Helper Functions:**  There are smaller helper functions for specific tasks like checking heap object types, comparing floating-point numbers bitwise, and handling API setters.

**Relationship to JavaScript:**

This code is deeply intertwined with how JavaScript property access is implemented at a low level in V8. The functions here directly correspond to operations like reading and writing object properties and array elements. The StubCache, for example, aims to speed up common property access patterns that occur frequently in JavaScript code.
这个C++代码文件（`v8/src/ic/accessor-assembler.cc` 的第二部分）主要定义了一些辅助函数，用于在V8的CodeStubAssembler（CSA）框架中生成处理JavaScript对象属性访问（读取和写入）的汇编代码。  它涵盖了更广泛的属性访问场景，包括处理快速属性、慢速属性（字典属性）、原型链查找、以及与内联缓存（Inline Caches，ICs）相关的逻辑。

以下是这个代码片段的主要功能归纳：

1. **类型检查和快速属性覆盖：**
   - `CheckFieldType`: 检查要写入的 `value` 是否与字段的类型匹配。
   - `OverwriteExistingFastDataProperty`:  负责覆盖对象上已存在的快速数据属性。它处理属性在对象内（in-object）还是在属性数组（backing store）中，以及不同的数据表示形式（Tagged、Double）。

2. **共享结构体属性存储：**
   - `StoreJSSharedStructField`:  处理向 `JSSharedStruct` 对象存储属性的操作，需要考虑并发访问。

3. **原型链有效性检查：**
   - `CheckPrototypeValidityCell`: 检查原型链的有效性，这对于确保优化的属性访问仍然正确至关重要。

4. **存储IC原型处理器处理：**
   - `HandleStoreICProtoHandler`: 这是处理存储操作的关键函数，当属性不在接收者自身，而是在其原型链上时会被调用。它根据不同的 `StoreHandler` 类型（例如，`kNormal`，`kSlow`，`kGlobalProxy`，`kAccessorFromPrototype`，`kNativeDataProperty`，`kApiSetter`）采取不同的操作。

5. **代理对象存储处理：**
   - `HandleStoreToProxy`:  专门处理向 `JSProxy` 对象存储属性的情况，这需要调用特定的代理处理逻辑。

6. **Smi处理器下的存储IC处理：**
   - `HandleStoreICSmiHandlerCase`:  当存储处理器是Smi时（通常表示快速属性访问），处理存储操作。它根据字段的表示形式（Tagged、HeapObject、Smi、Double）进行不同的检查和存储。

7. **字段存储和返回：**
   - `HandleStoreFieldAndReturn`:  执行实际的字段存储操作，并处理常量字段的情况。

8. **扩展属性后备存储：**
   - `ExtendPropertiesBackingStore`:  当需要更多空间来存储属性时，扩展对象的属性数组。

9. **元素访问（加载）：**
   - `EmitFastElementsBoundsCheck`:  在访问快速元素时进行边界检查。
   - `EmitElementLoad`:  处理各种元素类型的加载操作，包括快速数组（packed和holey）、双精度浮点数数组、以及各种类型的TypedArray。它处理越界访问和空洞（holes）的情况。

10. **原型有效性失效：**
    - `InvalidateValidityCellIfPrototype`: 如果一个Map是原型Map，则使其关联的有效性单元失效，因为对原型的修改会影响依赖于该原型的对象。

11. **通用元素加载：**
    - `GenericElementLoad`: 提供一个通用的元素加载机制，处理各种对象类型和元素访问场景，包括字符串的字符访问。

12. **通用属性加载：**
    - `GenericPropertyLoad`: 提供一个通用的属性加载机制，包括在对象自身查找、在原型链上查找、以及与内联缓存的交互。

13. **Stub Cache访问助手：**
    - 定义了与Stub Cache交互的辅助函数，例如 `StubCachePrimaryOffset`，`StubCacheSecondaryOffset`，`TryProbeStubCacheTable`，`TryProbeStubCache`。Stub Cache用于缓存最近使用的属性访问模式，以提高性能。

14. **LoadIC入口点：**
    - `LoadIC_BytecodeHandler`:  作为从字节码调用的LoadIC的入口点，包含了快速路径和慢速路径的处理。
    - `LoadIC`:  LoadIC的入口点，用于处理属性加载操作，包括单态（monomorphic）和多态（polymorphic）的情况，并尝试使用Stub Cache。
    - `LoadSuperIC`:  类似于LoadIC，但专门用于处理 `super` 关键字的属性访问。

**与JavaScript功能的关系：**

这个代码直接关系到JavaScript中对象属性的读取和写入操作。例如：

```javascript
const obj = { a: 1, b: 2 };
console.log(obj.a); //  对应 LoadIC 或 GenericPropertyLoad
obj.c = 3;          //  对应 StoreIC 或 HandleStoreICProtoHandler, OverwriteExistingFastDataProperty

const arr = [10, 20];
console.log(arr[0]); // 对应 EmitElementLoad 或 GenericElementLoad
arr[1] = 30;        // 对应 数组元素的存储逻辑

class Parent {
  constructor() {
    this.parentProp = 'parent';
  }
}

class Child extends Parent {
  constructor() {
    super();
    this.childProp = 'child';
  }

  getChildProp() {
    return super.parentProp; // 对应 LoadSuperIC
  }
}

const child = new Child();
console.log(child.childProp); // 对应 LoadIC 或 GenericPropertyLoad
```

- 当访问 `obj.a` 时，V8会尝试使用内联缓存（ICs）来优化这个操作。如果之前已经访问过 `obj` 的属性，可能会命中单态或多态的IC。如果未命中，则会进入更通用的属性加载流程（`GenericPropertyLoad`）。
- 当执行 `obj.c = 3` 时，V8会调用相应的存储IC处理器（`HandleStoreICProtoHandler` 等），根据对象的状态（例如，是否是快速属性对象）来执行存储操作。
- 访问数组元素 `arr[0]` 会触发元素加载逻辑（`EmitElementLoad`），V8会根据数组的元素类型（例如，packed Smi、holey element）进行高效的访问。
- 使用 `super.parentProp` 会触发 `LoadSuperIC`，V8需要沿着原型链向上查找 `parentProp`。

总而言之，这个代码片段是V8引擎实现JavaScript对象模型和属性访问机制的核心部分，它直接影响着JavaScript代码的执行效率。通过内联缓存、快速属性访问等优化手段，V8力求以高性能的方式执行JavaScript代码。

### 提示词
```
这是目录为v8/src/ic/accessor-assembler.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```
= FieldType::Any().ptr();
    // FieldType::Any can hold any value.
    GotoIf(
        TaggedEqual(field_type, BitcastWordToTagged(IntPtrConstant(kAnyType))),
        &all_fine);
    // FieldType::Class(...) performs a map check.
    // If the type is None we want this check to fail too, thus we compare the
    // maybe weak field type as is against a weak map ptr.
#ifdef DEBUG
    {
      // Check the field type is None or a weak map.
      Label check_done(this);
      GotoIf(TaggedEqual(field_type, BitcastWordToTagged(IntPtrConstant(
                                         FieldType::None().ptr()))),
             &check_done);
      CSA_DCHECK(this, IsMap(GetHeapObjectAssumeWeak(field_type)));
      Goto(&check_done);
      BIND(&check_done);
    }
#endif  // DEBUG
    Branch(TaggedEqual(MakeWeak(LoadMap(CAST(value))), field_type), &all_fine,
           bailout);
  }

  BIND(&all_fine);
}

TNode<BoolT> AccessorAssembler::IsPropertyDetailsConst(TNode<Uint32T> details) {
  return Word32Equal(
      DecodeWord32<PropertyDetails::ConstnessField>(details),
      Int32Constant(static_cast<int32_t>(PropertyConstness::kConst)));
}

void AccessorAssembler::OverwriteExistingFastDataProperty(
    TNode<HeapObject> object, TNode<Map> object_map,
    TNode<DescriptorArray> descriptors, TNode<IntPtrT> descriptor_name_index,
    TNode<Uint32T> details, TNode<Object> value, Label* slow,
    bool do_transitioning_store) {
  Label done(this), if_field(this), if_descriptor(this);

  CSA_DCHECK(this,
             Word32Equal(DecodeWord32<PropertyDetails::KindField>(details),
                         Int32Constant(static_cast<int>(PropertyKind::kData))));

  Branch(Word32Equal(
             DecodeWord32<PropertyDetails::LocationField>(details),
             Int32Constant(static_cast<int32_t>(PropertyLocation::kField))),
         &if_field, &if_descriptor);

  BIND(&if_field);
  {
    TNode<Uint32T> representation =
        DecodeWord32<PropertyDetails::RepresentationField>(details);

    CheckFieldType(descriptors, descriptor_name_index, representation, value,
                   slow);

    TNode<UintPtrT> field_index =
        DecodeWordFromWord32<PropertyDetails::FieldIndexField>(details);
    field_index = Unsigned(
        IntPtrAdd(field_index,
                  Unsigned(LoadMapInobjectPropertiesStartInWords(object_map))));
    TNode<IntPtrT> instance_size_in_words =
        LoadMapInstanceSizeInWords(object_map);

    Label inobject(this), backing_store(this);
    Branch(UintPtrLessThan(field_index, instance_size_in_words), &inobject,
           &backing_store);

    BIND(&inobject);
    {
      TNode<IntPtrT> field_offset = Signed(TimesTaggedSize(field_index));
      Label tagged_rep(this), double_rep(this);
      Branch(
          Word32Equal(representation, Int32Constant(Representation::kDouble)),
          &double_rep, &tagged_rep);
      BIND(&double_rep);
      {
        TNode<Float64T> double_value = ChangeNumberToFloat64(CAST(value));
        if (do_transitioning_store) {
          TNode<HeapNumber> heap_number =
              AllocateHeapNumberWithValue(double_value);
          StoreMap(object, object_map);
          StoreObjectField(object, field_offset, heap_number);
        } else {
          GotoIf(IsPropertyDetailsConst(details), slow);
          TNode<HeapNumber> heap_number =
              CAST(LoadObjectField(object, field_offset));
          StoreHeapNumberValue(heap_number, double_value);
        }
        Goto(&done);
      }

      BIND(&tagged_rep);
      {
        if (do_transitioning_store) {
          StoreMap(object, object_map);
        } else {
          GotoIf(IsPropertyDetailsConst(details), slow);
        }
        StoreObjectField(object, field_offset, value);
        Goto(&done);
      }
    }

    BIND(&backing_store);
    {
      TNode<IntPtrT> backing_store_index =
          Signed(IntPtrSub(field_index, instance_size_in_words));

      if (do_transitioning_store) {
        // Allocate mutable heap number before extending properties backing
        // store to ensure that heap verifier will not see the heap in
        // inconsistent state.
        TVARIABLE(Object, var_value, value);
        {
          Label cont(this);
          GotoIf(Word32NotEqual(representation,
                                Int32Constant(Representation::kDouble)),
                 &cont);
          {
            TNode<Float64T> double_value = ChangeNumberToFloat64(CAST(value));
            TNode<HeapNumber> heap_number =
                AllocateHeapNumberWithValue(double_value);
            var_value = heap_number;
            Goto(&cont);
          }
          BIND(&cont);
        }

        TNode<PropertyArray> properties =
            ExtendPropertiesBackingStore(object, backing_store_index);
        StorePropertyArrayElement(properties, backing_store_index,
                                  var_value.value());
        StoreMap(object, object_map);
        Goto(&done);

      } else {
        Label tagged_rep(this), double_rep(this);
        TNode<PropertyArray> properties =
            CAST(LoadFastProperties(CAST(object), true));
        Branch(
            Word32Equal(representation, Int32Constant(Representation::kDouble)),
            &double_rep, &tagged_rep);
        BIND(&double_rep);
        {
          GotoIf(IsPropertyDetailsConst(details), slow);
          TNode<HeapNumber> heap_number =
              CAST(LoadPropertyArrayElement(properties, backing_store_index));
          TNode<Float64T> double_value = ChangeNumberToFloat64(CAST(value));
          StoreHeapNumberValue(heap_number, double_value);
          Goto(&done);
        }
        BIND(&tagged_rep);
        {
          GotoIf(IsPropertyDetailsConst(details), slow);
          StorePropertyArrayElement(properties, backing_store_index, value);
          Goto(&done);
        }
      }
    }
  }

  BIND(&if_descriptor);
  {
    // Check that constant matches value.
    TNode<Object> constant =
        LoadValueByKeyIndex(descriptors, descriptor_name_index);
    GotoIf(TaggedNotEqual(value, constant), slow);

    if (do_transitioning_store) {
      StoreMap(object, object_map);
    }
    Goto(&done);
  }
  BIND(&done);
}

void AccessorAssembler::StoreJSSharedStructField(
    TNode<Context> context, TNode<HeapObject> shared_struct,
    TNode<Map> shared_struct_map, TNode<DescriptorArray> descriptors,
    TNode<IntPtrT> descriptor_name_index, TNode<Uint32T> details,
    TNode<Object> maybe_local_value) {
  CSA_DCHECK(this, IsJSSharedStruct(shared_struct));

  Label done(this);

  TNode<UintPtrT> field_index =
      DecodeWordFromWord32<PropertyDetails::FieldIndexField>(details);
  field_index = Unsigned(IntPtrAdd(
      field_index,
      Unsigned(LoadMapInobjectPropertiesStartInWords(shared_struct_map))));

  TNode<IntPtrT> instance_size_in_words =
      LoadMapInstanceSizeInWords(shared_struct_map);

  TVARIABLE(Object, shared_value, maybe_local_value);
  SharedValueBarrier(context, &shared_value);

  Label inobject(this), backing_store(this);
  Branch(UintPtrLessThan(field_index, instance_size_in_words), &inobject,
         &backing_store);

  BIND(&inobject);
  {
    TNode<IntPtrT> field_offset = Signed(TimesTaggedSize(field_index));
    StoreSharedObjectField(shared_struct, field_offset, shared_value.value());
    Goto(&done);
  }

  BIND(&backing_store);
  {
    TNode<IntPtrT> backing_store_index =
        Signed(IntPtrSub(field_index, instance_size_in_words));

    CSA_DCHECK(
        this,
        Word32Equal(DecodeWord32<PropertyDetails::RepresentationField>(details),
                    Int32Constant(Representation::kTagged)));
    TNode<PropertyArray> properties =
        CAST(LoadFastProperties(CAST(shared_struct), true));
    StoreJSSharedStructPropertyArrayElement(properties, backing_store_index,
                                            shared_value.value());
    Goto(&done);
  }

  BIND(&done);
}

void AccessorAssembler::CheckPrototypeValidityCell(
    TNode<Object> maybe_validity_cell, Label* miss) {
  Label done(this);
  GotoIf(
      TaggedEqual(maybe_validity_cell, SmiConstant(Map::kPrototypeChainValid)),
      &done);
  CSA_DCHECK(this, TaggedIsNotSmi(maybe_validity_cell));

  TNode<Object> cell_value =
      LoadObjectField(CAST(maybe_validity_cell), Cell::kValueOffset);
  Branch(TaggedEqual(cell_value, SmiConstant(Map::kPrototypeChainValid)), &done,
         miss);

  BIND(&done);
}

void AccessorAssembler::HandleStoreICProtoHandler(
    const StoreICParameters* p, TNode<StoreHandler> handler, Label* slow,
    Label* miss, ICMode ic_mode, ElementSupport support_elements) {
  Comment("HandleStoreICProtoHandler");

  OnCodeHandler on_code_handler;
  if (support_elements == kSupportElements) {
    // Code sub-handlers are expected only in KeyedStoreICs.
    on_code_handler = [=, this](TNode<Code> code_handler) {
      // This is either element store or transitioning element store.
      Label if_element_store(this), if_transitioning_element_store(this);
      Branch(IsStoreHandler0Map(LoadMap(handler)), &if_element_store,
             &if_transitioning_element_store);
      BIND(&if_element_store);
      {
        TailCallStub(StoreWithVectorDescriptor{}, code_handler, p->context(),
                     p->receiver(), p->name(), p->value(), p->slot(),
                     p->vector());
      }

      BIND(&if_transitioning_element_store);
      {
        TNode<MaybeObject> maybe_transition_map =
            LoadHandlerDataField(handler, 1);
        TNode<Map> transition_map =
            CAST(GetHeapObjectAssumeWeak(maybe_transition_map, miss));

        GotoIf(IsDeprecatedMap(transition_map), miss);

        TailCallStub(StoreTransitionDescriptor{}, code_handler, p->context(),
                     p->receiver(), p->name(), transition_map, p->value(),
                     p->slot(), p->vector());
      }
    };
  }

  TNode<Object> smi_handler = HandleProtoHandler<StoreHandler>(
      p, handler, on_code_handler,
      // on_found_on_lookup_start_object
      [=, this](TNode<PropertyDictionary> properties,
                TNode<IntPtrT> name_index) {
        TNode<Uint32T> details = LoadDetailsByKeyIndex(properties, name_index);
        // Check that the property is a writable data property (no accessor).
        const int kTypeAndReadOnlyMask =
            PropertyDetails::KindField::kMask |
            PropertyDetails::kAttributesReadOnlyMask;
        static_assert(static_cast<int>(PropertyKind::kData) == 0);
        GotoIf(IsSetWord32(details, kTypeAndReadOnlyMask), miss);

        StoreValueByKeyIndex<PropertyDictionary>(properties, name_index,
                                                 p->value());
        Return(p->value());
      },
      miss, ic_mode);

  {
    Label if_add_normal(this), if_store_global_proxy(this), if_api_setter(this),
        if_accessor(this), if_native_data_property(this);

    CSA_DCHECK(this, TaggedIsSmi(smi_handler));
    TNode<Int32T> handler_word = SmiToInt32(CAST(smi_handler));

    TNode<Uint32T> handler_kind =
        DecodeWord32<StoreHandler::KindBits>(handler_word);
    GotoIf(Word32Equal(handler_kind, STORE_KIND(kNormal)), &if_add_normal);

    GotoIf(Word32Equal(handler_kind, STORE_KIND(kSlow)), slow);

    TNode<MaybeObject> maybe_holder = LoadHandlerDataField(handler, 1);
    CSA_DCHECK(this, IsWeakOrCleared(maybe_holder));
    TNode<HeapObject> holder = GetHeapObjectAssumeWeak(maybe_holder, miss);

    GotoIf(Word32Equal(handler_kind, STORE_KIND(kGlobalProxy)),
           &if_store_global_proxy);

    GotoIf(Word32Equal(handler_kind, STORE_KIND(kAccessorFromPrototype)),
           &if_accessor);

    GotoIf(Word32Equal(handler_kind, STORE_KIND(kNativeDataProperty)),
           &if_native_data_property);

    GotoIf(Word32Equal(handler_kind, STORE_KIND(kApiSetter)), &if_api_setter);

    GotoIf(Word32Equal(handler_kind, STORE_KIND(kApiSetterHolderIsPrototype)),
           &if_api_setter);

    CSA_DCHECK(this, Word32Equal(handler_kind, STORE_KIND(kProxy)));
    HandleStoreToProxy(p, CAST(holder), miss, support_elements);

    BIND(&if_add_normal);
    {
      // This is a case of "transitioning store" to a dictionary mode object
      // when the property does not exist. The "existing property" case is
      // covered above by LookupOnLookupStartObject bit handling of the smi
      // handler.
      Label slow(this);
      TNode<Map> receiver_map = LoadMap(CAST(p->receiver()));
      InvalidateValidityCellIfPrototype(receiver_map);

      TNode<PropertyDictionary> properties =
          CAST(LoadSlowProperties(CAST(p->receiver())));
      TNode<Name> name = CAST(p->name());
      AddToDictionary<PropertyDictionary>(properties, name, p->value(), &slow);
      UpdateMayHaveInterestingProperty(properties, name);
      Return(p->value());

      BIND(&slow);
      TailCallRuntime(Runtime::kAddDictionaryProperty, p->context(),
                      p->receiver(), p->name(), p->value());
    }

    BIND(&if_accessor);
    {
      Comment("accessor_store");
      // The "holder" slot (data1) in the from-prototype StoreHandler is
      // instead directly the setter function.
      TNode<JSFunction> setter = CAST(holder);

      // As long as this code path is not used for StoreSuperIC the receiver
      // is known to be neither undefined nor null.
      ConvertReceiverMode mode = ConvertReceiverMode::kNotNullOrUndefined;
      Return(
          CallFunction(p->context(), setter, mode, p->receiver(), p->value()));
    }

    BIND(&if_native_data_property);
    HandleStoreICNativeDataProperty(p, holder, handler_word);

    BIND(&if_api_setter);
    {
      Comment("api_setter");
      CSA_DCHECK(this, TaggedIsNotSmi(handler));
      TNode<FunctionTemplateInfo> function_template_info = CAST(holder);

      // Context is stored either in data2 or data3 field depending on whether
      // the access check is enabled for this handler or not.
      TNode<MaybeObject> maybe_context = Select<MaybeObject>(
          IsSetWord32<StoreHandler::DoAccessCheckOnLookupStartObjectBits>(
              handler_word),
          [=, this] { return LoadHandlerDataField(handler, 3); },
          [=, this] { return LoadHandlerDataField(handler, 2); });

      CSA_DCHECK(this, IsWeakOrCleared(maybe_context));
      TNode<Object> context = Select<Object>(
          IsCleared(maybe_context), [=, this] { return SmiConstant(0); },
          [=, this] { return GetHeapObjectAssumeWeak(maybe_context); });

      TVARIABLE(Object, api_holder, p->receiver());
      Label store(this);
      GotoIf(Word32Equal(handler_kind, STORE_KIND(kApiSetter)), &store);

      CSA_DCHECK(this, Word32Equal(handler_kind,
                                   STORE_KIND(kApiSetterHolderIsPrototype)));

      api_holder = LoadMapPrototype(LoadMap(CAST(p->receiver())));
      Goto(&store);

      BIND(&store);
      {
        TNode<Int32T> argc = Int32Constant(1);
        TNode<Context> caller_context = p->context();
        Return(CallBuiltin(Builtin::kCallApiCallbackGeneric, context, argc,
                           caller_context, function_template_info,
                           api_holder.value(), p->receiver(), p->value()));
      }
    }

    BIND(&if_store_global_proxy);
    {
      ExitPoint direct_exit(this);
      // StoreGlobalIC_PropertyCellCase doesn't properly handle private names
      // but they are not expected here anyway.
      CSA_DCHECK(this, BoolConstant(!p->IsDefineKeyedOwn()));
      StoreGlobalIC_PropertyCellCase(CAST(holder), p->value(), &direct_exit,
                                     miss);
    }
  }
}

void AccessorAssembler::HandleStoreToProxy(const StoreICParameters* p,
                                           TNode<JSProxy> proxy, Label* miss,
                                           ElementSupport support_elements) {
  TVARIABLE(IntPtrT, var_index);
  TVARIABLE(Name, var_unique);

  Label if_index(this), if_unique_name(this),
      to_name_failed(this, Label::kDeferred);

  if (support_elements == kSupportElements) {
    TryToName(p->name(), &if_index, &var_index, &if_unique_name, &var_unique,
              &to_name_failed);

    BIND(&if_unique_name);
    CallBuiltin(Builtin::kProxySetProperty, p->context(), proxy,
                var_unique.value(), p->value(), p->receiver());
    Return(p->value());

    // The index case is handled earlier by the runtime.
    BIND(&if_index);
    // TODO(mslekova): introduce TryToName that doesn't try to compute
    // the intptr index value
    Goto(&to_name_failed);

    BIND(&to_name_failed);
    TailCallRuntime(Runtime::kSetPropertyWithReceiver, p->context(), proxy,
                    p->name(), p->value(), p->receiver());
  } else {
    TNode<Object> name = CallBuiltin(Builtin::kToName, p->context(), p->name());
    TailCallBuiltin(Builtin::kProxySetProperty, p->context(), proxy, name,
                    p->value(), p->receiver());
  }
}

void AccessorAssembler::HandleStoreICSmiHandlerCase(TNode<Word32T> handler_word,
                                                    TNode<JSObject> holder,
                                                    TNode<Object> value,
                                                    Label* miss) {
  Comment("field store");
#ifdef DEBUG
  TNode<Uint32T> handler_kind =
      DecodeWord32<StoreHandler::KindBits>(handler_word);
  CSA_DCHECK(this,
             Word32Or(Word32Equal(handler_kind, STORE_KIND(kField)),
                      Word32Equal(handler_kind, STORE_KIND(kConstField))));
#endif

  TNode<Uint32T> field_representation =
      DecodeWord32<StoreHandler::RepresentationBits>(handler_word);

  Label if_smi_field(this), if_double_field(this), if_heap_object_field(this),
      if_tagged_field(this);

  int32_t case_values[] = {Representation::kTagged, Representation::kHeapObject,
                           Representation::kSmi};
  Label* case_labels[] = {&if_tagged_field, &if_heap_object_field,
                          &if_smi_field};

  Switch(field_representation, &if_double_field, case_values, case_labels, 3);

  BIND(&if_tagged_field);
  {
    Comment("store tagged field");
    HandleStoreFieldAndReturn(handler_word, holder, value, std::nullopt,
                              Representation::Tagged(), miss);
  }

  BIND(&if_heap_object_field);
  {
    Comment("heap object field checks");
    CheckHeapObjectTypeMatchesDescriptor(handler_word, holder, value, miss);

    Comment("store heap object field");
    HandleStoreFieldAndReturn(handler_word, holder, value, std::nullopt,
                              Representation::HeapObject(), miss);
  }

  BIND(&if_smi_field);
  {
    Comment("smi field checks");
    GotoIfNot(TaggedIsSmi(value), miss);

    Comment("store smi field");
    HandleStoreFieldAndReturn(handler_word, holder, value, std::nullopt,
                              Representation::Smi(), miss);
  }

  BIND(&if_double_field);
  {
    CSA_DCHECK(this, Word32Equal(field_representation,
                                 Int32Constant(Representation::kDouble)));
    Comment("double field checks");
    TNode<Float64T> double_value = TryTaggedToFloat64(value, miss);
    CheckDescriptorConsidersNumbersMutable(handler_word, holder, miss);

    Comment("store double field");
    HandleStoreFieldAndReturn(handler_word, holder, value, double_value,
                              Representation::Double(), miss);
  }
}

void AccessorAssembler::CheckHeapObjectTypeMatchesDescriptor(
    TNode<Word32T> handler_word, TNode<JSObject> holder, TNode<Object> value,
    Label* bailout) {
  GotoIf(TaggedIsSmi(value), bailout);

  Label done(this);
  // Skip field type check in favor of constant value check when storing
  // to constant field.
  GotoIf(Word32Equal(DecodeWord32<StoreHandler::KindBits>(handler_word),
                     STORE_KIND(kConstField)),
         &done);
  TNode<IntPtrT> descriptor =
      Signed(DecodeWordFromWord32<StoreHandler::DescriptorBits>(handler_word));
  TNode<MaybeObject> field_type =
      LoadDescriptorValueOrFieldType(LoadMap(holder), descriptor);

  const Address kAnyType = FieldType::Any().ptr();
  GotoIf(TaggedEqual(field_type, BitcastWordToTagged(IntPtrConstant(kAnyType))),
         &done);
  // Check that value type matches the field type.
  {
    // If the type is None we want this check to fail too, thus we compare the
    // maybe weak field type as is against a weak map ptr.
#ifdef DEBUG
    {
      // Check the field type is None or a weak map.
      Label check_done(this);
      GotoIf(TaggedEqual(field_type, BitcastWordToTagged(IntPtrConstant(
                                         FieldType::None().ptr()))),
             &check_done);
      CSA_DCHECK(this, IsMap(GetHeapObjectAssumeWeak(field_type)));
      Goto(&check_done);
      BIND(&check_done);
    }
#endif  // DEBUG
    Branch(TaggedEqual(MakeWeak(LoadMap(CAST(value))), field_type), &done,
           bailout);
  }
  BIND(&done);
}

void AccessorAssembler::CheckDescriptorConsidersNumbersMutable(
    TNode<Word32T> handler_word, TNode<JSObject> holder, Label* bailout) {
  // We have to check that the representation is Double. Checking the value
  // (either in the field or being assigned) is not enough, as we could have
  // transitioned to Tagged but still be holding a HeapNumber, which would no
  // longer be allowed to be mutable.

  // TODO(leszeks): We could skip the representation check in favor of a
  // constant value check in HandleStoreFieldAndReturn here, but then
  // HandleStoreFieldAndReturn would need an IsHeapNumber check in case both the
  // representation changed and the value is no longer a HeapNumber.
  TNode<IntPtrT> descriptor_entry =
      Signed(DecodeWordFromWord32<StoreHandler::DescriptorBits>(handler_word));
  TNode<DescriptorArray> descriptors = LoadMapDescriptors(LoadMap(holder));
  TNode<Uint32T> details =
      LoadDetailsByDescriptorEntry(descriptors, descriptor_entry);

  GotoIfNot(IsEqualInWord32<PropertyDetails::RepresentationField>(
                details, Representation::kDouble),
            bailout);
}

void AccessorAssembler::GotoIfNotSameNumberBitPattern(TNode<Float64T> left,
                                                      TNode<Float64T> right,
                                                      Label* miss) {
  // TODO(verwaest): Use a single compare on 64bit archs.
  const TNode<Uint32T> lhs_hi = Float64ExtractHighWord32(left);
  const TNode<Uint32T> rhs_hi = Float64ExtractHighWord32(right);
  GotoIfNot(Word32Equal(lhs_hi, rhs_hi), miss);
  const TNode<Uint32T> lhs_lo = Float64ExtractLowWord32(left);
  const TNode<Uint32T> rhs_lo = Float64ExtractLowWord32(right);
  GotoIfNot(Word32Equal(lhs_lo, rhs_lo), miss);
}

void AccessorAssembler::HandleStoreFieldAndReturn(
    TNode<Word32T> handler_word, TNode<JSObject> holder, TNode<Object> value,
    std::optional<TNode<Float64T>> double_value, Representation representation,
    Label* miss) {
  bool store_value_as_double = representation.IsDouble();

  TNode<BoolT> is_inobject =
      IsSetWord32<StoreHandler::IsInobjectBits>(handler_word);
  TNode<HeapObject> property_storage = Select<HeapObject>(
      is_inobject, [&]() { return holder; },
      [&]() { return LoadFastProperties(holder, true); });

  TNode<UintPtrT> index =
      DecodeWordFromWord32<StoreHandler::FieldIndexBits>(handler_word);
  TNode<IntPtrT> offset = Signed(TimesTaggedSize(index));

  // For Double fields, we want to mutate the current double-value
  // field rather than changing it to point at a new HeapNumber.
  if (store_value_as_double) {
    TVARIABLE(HeapObject, actual_property_storage, property_storage);
    TVARIABLE(IntPtrT, actual_offset, offset);

    Label property_and_offset_ready(this);

    // Store the double value directly into the mutable HeapNumber.
    TNode<Object> field = LoadObjectField(property_storage, offset);
    CSA_DCHECK(this, IsHeapNumber(CAST(field)));
    actual_property_storage = CAST(field);
    actual_offset = IntPtrConstant(offsetof(HeapNumber, value_));
    Goto(&property_and_offset_ready);

    BIND(&property_and_offset_ready);
    property_storage = actual_property_storage.value();
    offset = actual_offset.value();
  }

  // Do constant value check if necessary.
  Label do_store(this);
  GotoIfNot(Word32Equal(DecodeWord32<StoreHandler::KindBits>(handler_word),
                        STORE_KIND(kConstField)),
            &do_store);
  {
    if (store_value_as_double) {
      TNode<Float64T> current_value =
          LoadObjectField<Float64T>(property_storage, offset);
      GotoIfNotSameNumberBitPattern(current_value, *double_value, miss);
      Return(value);
    } else {
      TNode<Object> current_value = LoadObjectField(property_storage, offset);
      GotoIfNot(TaggedEqual(current_value, value), miss);
      Return(value);
    }
  }

  BIND(&do_store);
  // Do the store.
  if (store_value_as_double) {
    StoreObjectFieldNoWriteBarrier(property_storage, offset, *double_value);
  } else if (representation.IsSmi()) {
    TNode<Smi> value_smi = CAST(value);
    StoreObjectFieldNoWriteBarrier(property_storage, offset, value_smi);
  } else {
    StoreObjectField(property_storage, offset, value);
  }

  Return(value);
}

TNode<PropertyArray> AccessorAssembler::ExtendPropertiesBackingStore(
    TNode<HeapObject> object, TNode<IntPtrT> index) {
  Comment("[ Extend storage");

  TVARIABLE(HeapObject, var_properties);
  TVARIABLE(Int32T, var_encoded_hash);
  TVARIABLE(IntPtrT, var_length);

  TNode<Object> properties =
      LoadObjectField(object, JSObject::kPropertiesOrHashOffset);

  Label if_smi_hash(this), if_property_array(this), extend_store(this);
  Branch(TaggedIsSmi(properties), &if_smi_hash, &if_property_array);

  BIND(&if_smi_hash);
  {
    TNode<Int32T> hash = SmiToInt32(CAST(properties));
    TNode<Int32T> encoded_hash =
        Word32Shl(hash, Int32Constant(PropertyArray::HashField::kShift));
    var_encoded_hash = encoded_hash;
    var_length = IntPtrConstant(0);
    var_properties = EmptyFixedArrayConstant();
    Goto(&extend_store);
  }

  BIND(&if_property_array);
  {
    var_properties = CAST(properties);
    TNode<Int32T> length_and_hash_int32 = LoadAndUntagToWord32ObjectField(
        var_properties.value(), PropertyArray::kLengthAndHashOffset);
    var_encoded_hash = Word32And(
        length_and_hash_int32, Int32Constant(PropertyArray::HashField::kMask));
    var_length = ChangeInt32ToIntPtr(
        Word32And(length_and_hash_int32,
                  Int32Constant(PropertyArray::LengthField::kMask)));
    Goto(&extend_store);
  }

  BIND(&extend_store);
  {
    TVARIABLE(HeapObject, var_new_properties, var_properties.value());
    Label done(this);
    // Previous property deletion could have left behind unused backing store
    // capacity even for a map that think it doesn't have any unused fields.
    // Perform a bounds check to see if we actually have to grow the array.
    GotoIf(UintPtrLessThan(index, ParameterToIntPtr(var_length.value())),
           &done);

    TNode<IntPtrT> delta = IntPtrConstant(JSObject::kFieldsAdded);
    TNode<IntPtrT> new_capacity = IntPtrAdd(var_length.value(), delta);

    // Grow properties array.
    DCHECK(kMaxNumberOfDescriptors + JSObject::kFieldsAdded <
           FixedArrayBase::GetMaxLengthForNewSpaceAllocation(PACKED_ELEMENTS));
    // The size of a new properties backing store is guaranteed to be small
    // enough that the new backing store will be allocated in new space.
    CSA_DCHECK(this, IntPtrLessThan(new_capacity,
                                    IntPtrConstant(kMaxNumberOfDescriptors +
                                                   JSObject::kFieldsAdded)));

    TNode<PropertyArray> new_properties = AllocatePropertyArray(new_capacity);
    var_new_properties = new_properties;

    FillPropertyArrayWithUndefined(new_properties, var_length.value(),
                                   new_capacity);

    // |new_properties| is guaranteed to be in new space, so we can skip
    // the write barrier.
    CopyPropertyArrayValues(var_properties.value(), new_properties,
                            var_length.value(), SKIP_WRITE_BARRIER,
                            DestroySource::kYes);

    TNode<Int32T> new_capacity_int32 = TruncateIntPtrToInt32(new_capacity);
    TNode<Int32T> new_length_and_hash_int32 =
        Word32Or(var_encoded_hash.value(), new_capacity_int32);
    StoreObjectField(new_properties, PropertyArray::kLengthAndHashOffset,
                     SmiFromInt32(new_length_and_hash_int32));
    StoreObjectField(object, JSObject::kPropertiesOrHashOffset, new_properties);
    Comment("] Extend storage");
    Goto(&done);
    BIND(&done);
    return CAST(var_new_properties.value());
  }
}

void AccessorAssembler::EmitFastElementsBoundsCheck(
    TNode<JSObject> object, TNode<FixedArrayBase> elements,
    TNode<IntPtrT> intptr_index, TNode<BoolT> is_jsarray_condition,
    Label* miss) {
  TVARIABLE(IntPtrT, var_length);
  Comment("Fast elements bounds check");
  Label if_array(this), length_loaded(this, &var_length);
  GotoIf(is_jsarray_condition, &if_array);
  {
    var_length = LoadAndUntagFixedArrayBaseLength(elements);
    Goto(&length_loaded);
  }
  BIND(&if_array);
  {
    var_length = PositiveSmiUntag(LoadFastJSArrayLength(CAST(object)));
    Goto(&length_loaded);
  }
  BIND(&length_loaded);
  GotoIfNot(UintPtrLessThan(intptr_index, var_length.value()), miss);
}

void AccessorAssembler::EmitElementLoad(
    TNode<HeapObject> object, TNode<Word32T> elements_kind,
    TNode<IntPtrT> intptr_index, TNode<BoolT> is_jsarray_condition,
    Label* if_hole, Label* rebox_double, TVariable<Float64T>* var_double_value,
    Label* unimplemented_elements_kind, Label* out_of_bounds, Label* miss,
    ExitPoint* exit_point, LoadAccessMode access_mode) {
  Label if_rab_gsab_typed_array(this), if_typed_array(this), if_fast(this),
      if_fast_packed(this), if_fast_holey(this), if_fast_double(this),
      if_fast_holey_double(this), if_nonfast(this), if_dictionary(this);
  Branch(Int32GreaterThan(elements_kind,
                          Int32Constant(LAST_ANY_NONEXTENSIBLE_ELEMENTS_KIND)),
         &if_nonfast, &if_fast);

  BIND(&if_fast);
  {
    TNode<FixedArrayBase> elements = LoadJSObjectElements(CAST(object));
    EmitFastElementsBoundsCheck(CAST(object), elements, intptr_index,
                                is_jsarray_condition, out_of_bounds);
    int32_t kinds[] = {
        // Handled by if_fast_packed.
        PACKED_SMI_ELEMENTS, PACKED_ELEMENTS, PACKED_NONEXTENSIBLE_ELEMENTS,
        PACKED_SEALED_ELEMENTS, PACKED_FROZEN_ELEMENTS, SHARED_ARRAY_ELEMENTS,
        // Handled by if_fast_holey.
        HOLEY_SMI_ELEMENTS, HOLEY_ELEMENTS, HOLEY_NONEXTENSIBLE_ELEMENTS,
        HOLEY_FROZEN_ELEMENTS, HOLEY_SEALED_ELEMENTS,
        // Handled by if_fast_double.
        PACKED_DOUBLE_ELEMENTS,
        // Handled by if_fast_holey_double.
        HOLEY_DOUBLE_ELEMENTS};
    Label* labels[] = {// FAST_{SMI,}_ELEMENTS
                       &if_fast_packed, &if_fast_packed, &if_fast_packed,
                       &if_fast_packed, &if_fast_packed, &if_fast_packed,
                       // FAST_HOLEY_{SMI,}_ELEMENTS
                       &if_fast_holey, &if_fast_holey, &if_fast_holey,
                       &if_fast_holey, &if_fast_holey,
                       // PACKED_DOUBLE_ELEMENTS
                       &if_fast_double,
                       // HOLEY_DOUBLE_ELEMENTS
                       &if_fast_holey_double};
    Switch(elements_kind, unimplemented_elements_kind, kinds, labels,
           arraysize(kinds));

    BIND(&if_fast_packed);
    {
      Comment("fast packed elements");
      exit_point->Return(
          access_mode == LoadAccessMode::kHas
              ? TrueConstant()
              : UnsafeLoadFixedArrayElement(CAST(elements), intptr_index));
    }

    BIND(&if_fast_holey);
    {
      Comment("fast holey elements");
      TNode<Object> element =
          UnsafeLoadFixedArrayElement(CAST(elements), intptr_index);
      GotoIf(TaggedEqual(element, TheHoleConstant()), if_hole);
      exit_point->Return(access_mode == LoadAccessMode::kHas ? TrueConstant()
                                                             : element);
    }

    BIND(&if_fast_double);
    {
      Comment("packed double elements");
      if (access_mode == LoadAccessMode::kHas) {
        exit_point->Return(TrueConstant());
      } else {
        *var_double_value =
            LoadFixedDoubleArrayElement(CAST(elements), intptr_index);
        Goto(rebox_double);
      }
    }

    BIND(&if_fast_holey_double);
    {
      Comment("holey double elements");
      TNode<Float64T> value =
          LoadFixedDoubleArrayElement(CAST(elements), intptr_index, if_hole);
      if (access_mode == LoadAccessMode::kHas) {
        exit_point->Return(TrueConstant());
      } else {
        *var_double_value = value;
        Goto(rebox_double);
      }
    }
  }

  BIND(&if_nonfast);
  {
    Label uint8_elements(this), int8_elements(this), uint16_elements(this),
        int16_elements(this), uint32_elements(this), int32_elements(this),
        float32_elements(this), float64_elements(this), bigint64_elements(this),
        biguint64_elements(this), float16_elements(this);
    static_assert(LAST_ELEMENTS_KIND ==
                  LAST_RAB_GSAB_FIXED_TYPED_ARRAY_ELEMENTS_KIND);
    GotoIf(Int32GreaterThanOrEqual(
               elements_kind,
               Int32Constant(FIRST_RAB_GSAB_FIXED_TYPED_ARRAY_ELEMENTS_KIND)),
           &if_rab_gsab_typed_array);
    GotoIf(Int32GreaterThanOrEqual(
               elements_kind,
               Int32Constant(FIRST_FIXED_TYPED_ARRAY_ELEMENTS_KIND)),
           &if_typed_array);
    GotoIf(Word32Equal(elements_kind, Int32Constant(DICTIONARY_ELEMENTS)),
           &if_dictionary);
    Goto(unimplemented_elements_kind);

    BIND(&if_dictionary);
    {
      Comment("dictionary elements");
      if (Is64()) {
        GotoIf(UintPtrLessThan(IntPtrConstant(JSObject::kMaxElementIndex),
                               intptr_index),
               out_of_bounds);
      } else {
        GotoIf(IntPtrLessThan(intptr_index, IntPtrConstant(0)), out_of_bounds);
      }

      TNode<FixedArrayBase> elements = LoadJSObjectElements(CAST(object));
      TNode<Object> value = BasicLoadNumberDictionaryElement(
          CAST(elements), intptr_index, miss, if_hole);
      exit_point->Return(access_mode == LoadAccessMode::kHas ? TrueConstant()
                                                             : value);
    }
    {
      TVARIABLE(RawPtrT, data_ptr);
      BIND(&if_rab_gsab_typed_array);
      {
        Comment("rab gsab typed elements");
        Label variable_length(this), normal(this), length_check_ok(this);

        TNode<JSTypedArray> array = CAST(object);
        TNode<JSArrayBuffer> buffer = LoadJSArrayBufferViewBuffer(array);

        // Bounds check (incl. detachedness check).
        TNode<UintPtrT> length =
            LoadVariableLengthJSTypedArrayLength(array, buffer, miss);
        Branch(UintPtrLessThan(intptr_index, length), &length_check_ok,
               out_of_bounds);
        BIND(&length_check_ok);
        {
          if (access_mode == LoadAccessMode::kHas) {
            exit_point->Return(TrueConstant());
          } else {
            data_ptr = LoadJSTypedArrayDataPtr(array);
            Label* elements_kind_labels[] = {
                &uint8_elements,    &uint8_elements,     &int8_elements,
                &uint16_elements,   &int16_elements,     &uint32_elements,
                &int32_elements,    &float32_elements,   &float64_elements,
                &bigint64_elements, &biguint64_elements, &float16_elements,
            };
            int32_t elements_kinds[] = {
                RAB_GSAB_UINT8_ELEMENTS,     RAB_GSAB_UINT8_CLAMPED_ELEMENTS,
                RAB_GSAB_INT8_ELEMENTS,      RAB_GSAB_UINT16_ELEMENTS,
                RAB_GSAB_INT16_ELEMENTS,     RAB_GSAB_UINT32_ELEMENTS,
                RAB_GSAB_INT32_ELEMENTS,     RAB_GSAB_FLOAT32_ELEMENTS,
                RAB_GSAB_FLOAT64_ELEMENTS,   RAB_GSAB_BIGINT64_ELEMENTS,
                RAB_GSAB_BIGUINT64_ELEMENTS, RAB_GSAB_FLOAT16_ELEMENTS};
            const size_t kTypedElementsKindCount =
                LAST_RAB_GSAB_FIXED_TYPED_ARRAY_ELEMENTS_KIND -
                FIRST_RAB_GSAB_FIXED_TYPED_ARRAY_ELEMENTS_KIND + 1;
            DCHECK_EQ(kTypedElementsKindCount, arraysize(elements_kinds));
            DCHECK_EQ(kTypedElementsKindCount, arraysize(elements_kind_labels));
            Switch(elements_kind, miss, elements_kinds, elements_kind_labels,
                   kTypedElementsKindCount);
          }
        }
      }
      BIND(&if_typed_array);
      {
        Comment("typed elements");
        // Check if buffer has been detached.
        TNode<JSArrayBuffer> buffer = LoadJSArrayBufferViewBuffer(CAST(object));
        GotoIf(IsDetachedBuffer(buffer), miss);

        // Bounds check.
        TNode<UintPtrT> length = LoadJSTypedArrayLength(CAST(object));
        GotoIfNot(UintPtrLessThan(intptr_index, length), out_of_bounds);
        if (access_mode == LoadAccessMode::kHas) {
          exit_point->Return(TrueConstant());
        } else {
          data_ptr = LoadJSTypedArrayDataPtr(CAST(object));

          Label* elements_kind_labels[] = {
              &uint8_elements,    &uint8_elements,     &int8_elements,
              &uint16_elements,   &int16_elements,     &uint32_elements,
              &int32_elements,    &float32_elements,   &float64_elements,
              &bigint64_elements, &biguint64_elements, &float16_elements};
          int32_t elements_kinds[] = {
              UINT8_ELEMENTS,    UINT8_CLAMPED_ELEMENTS, INT8_ELEMENTS,
              UINT16_ELEMENTS,   INT16_ELEMENTS,         UINT32_ELEMENTS,
              INT32_ELEMENTS,    FLOAT32_ELEMENTS,       FLOAT64_ELEMENTS,
              BIGINT64_ELEMENTS, BIGUINT64_ELEMENTS,     FLOAT16_ELEMENTS};
          const size_t kTypedElementsKindCount =
              LAST_FIXED_TYPED_ARRAY_ELEMENTS_KIND -
              FIRST_FIXED_TYPED_ARRAY_ELEMENTS_KIND + 1;
          DCHECK_EQ(kTypedElementsKindCount, arraysize(elements_kinds));
          DCHECK_EQ(kTypedElementsKindCount, arraysize(elements_kind_labels));
          Switch(elements_kind, miss, elements_kinds, elements_kind_labels,
                 kTypedElementsKindCount);
        }
      }
      if (access_mode != LoadAccessMode::kHas) {
        BIND(&uint8_elements);
        {
          Comment("UINT8_ELEMENTS");  // Handles UINT8_CLAMPED_ELEMENTS too.
          TNode<Int32T> element = Load<Uint8T>(data_ptr.value(), intptr_index);
          exit_point->Return(SmiFromInt32(element));
        }
        BIND(&int8_elements);
        {
          Comment("INT8_ELEMENTS");
          TNode<Int32T> element = Load<Int8T>(data_ptr.value(), intptr_index);
          exit_point->Return(SmiFromInt32(element));
        }
        BIND(&uint16_elements);
        {
          Comment("UINT16_ELEMENTS");
          TNode<IntPtrT> index = WordShl(intptr_index, IntPtrConstant(1));
          TNode<Int32T> element = Load<Uint16T>(data_ptr.value(), index);
          exit_point->Return(SmiFromInt32(element));
        }
        BIND(&int16_elements);
        {
          Comment("INT16_ELEMENTS");
          TNode<IntPtrT> index = WordShl(intptr_index, IntPtrConstant(1));
          TNode<Int32T> element = Load<Int16T>(data_ptr.value(), index);
          exit_point->Return(SmiFromInt32(element));
        }
        BIND(&uint32_elements);
        {
          Comment("UINT32_ELEMENTS");
          TNode<IntPtrT> index = WordShl(intptr_index, IntPtrConstant(2));
          TNode<Uint32T> element = Load<Uint32T>(data_ptr.value(), index);
          exit_point->Return(ChangeUint32ToTagged(element));
        }
        BIND(&int32_elements);
        {
          Comment("INT32_ELEMENTS");
          TNode<IntPtrT> index = WordShl(intptr_index, IntPtrConstant(2));
          TNode<Int32T> element = Load<Int32T>(data_ptr.value(), index);
          exit_point->Return(ChangeInt32ToTagged(element));
        }
        BIND(&float16_elements);
        {
          Comment("FLOAT16_ELEMENTS");
          TNode<IntPtrT> index = WordShl(intptr_index, IntPtrConstant(1));
          TNode<Float16RawBitsT> raw_element =
              Load<Float16RawBitsT>(data_ptr.value(), index);
          *var_double_value = ChangeFloat16ToFloat64(raw_element);
          Goto(rebox_double);
        }
        BIND(&float32_elements);
        {
          Comment("FLOAT32_ELEMENTS");
          TNode<IntPtrT> index = WordShl(intptr_index, IntPtrConstant(2));
          TNode<Float32T> element = Load<Float32T>(data_ptr.value(), index);
          *var_double_value = ChangeFloat32ToFloat64(element);
          Goto(rebox_double);
        }
        BIND(&float64_elements);
        {
          Comment("FLOAT64_ELEMENTS");
          TNode<IntPtrT> index = WordShl(intptr_index, IntPtrConstant(3));
          TNode<Float64T> element = Load<Float64T>(data_ptr.value(), index);
          *var_double_value = element;
          Goto(rebox_double);
        }
        BIND(&bigint64_elements);
        {
          Comment("BIGINT64_ELEMENTS");
          exit_point->Return(LoadFixedTypedArrayElementAsTagged(
              data_ptr.value(), Unsigned(intptr_index), BIGINT64_ELEMENTS));
        }
        BIND(&biguint64_elements);
        {
          Comment("BIGUINT64_ELEMENTS");
          exit_point->Return(LoadFixedTypedArrayElementAsTagged(
              data_ptr.value(), Unsigned(intptr_index), BIGUINT64_ELEMENTS));
        }
      }
    }
  }
}

void AccessorAssembler::InvalidateValidityCellIfPrototype(
    TNode<Map> map, std::optional<TNode<Uint32T>> maybe_bitfield3) {
  Label is_prototype(this), cont(this);
  TNode<Uint32T> bitfield3;
  if (maybe_bitfield3) {
    bitfield3 = maybe_bitfield3.value();
  } else {
    bitfield3 = LoadMapBitField3(map);
  }

  Branch(IsSetWord32(bitfield3, Map::Bits3::IsPrototypeMapBit::kMask),
         &is_prototype, &cont);

  BIND(&is_prototype);
  {
    TNode<Object> maybe_prototype_info =
        LoadObjectField(map, Map::kTransitionsOrPrototypeInfoOffset);
    // If there's no prototype info then there's nothing to invalidate.
    GotoIf(TaggedIsSmi(maybe_prototype_info), &cont);

    TNode<ExternalReference> function = ExternalConstant(
        ExternalReference::invalidate_prototype_chains_function());
    CallCFunction(function, MachineType::AnyTagged(),
                  std::make_pair(MachineType::AnyTagged(), map));
    Goto(&cont);
  }
  BIND(&cont);
}

void AccessorAssembler::GenericElementLoad(
    TNode<HeapObject> lookup_start_object, TNode<Map> lookup_start_object_map,
    TNode<Int32T> lookup_start_object_instance_type, TNode<IntPtrT> index,
    Label* slow) {
  Comment("integer index");

  ExitPoint direct_exit(this);

  Label if_custom(this), if_element_hole(this), if_oob(this);
  Label return_undefined(this);
  // Receivers requiring non-standard element accesses (interceptors, access
  // checks, strings and string wrappers, proxies) are handled in the runtime.
  GotoIf(
      IsCustomElementsReceiverInstanceType(lookup_start_object_instance_type),
      &if_custom);
  TNode<Int32T> elements_kind = LoadMapElementsKind(lookup_start_object_map);
  TNode<BoolT> is_jsarray_condition =
      IsJSArrayInstanceType(lookup_start_object_instance_type);
  TVARIABLE(Float64T, var_double_value);
  Label rebox_double(this, &var_double_value);

  // Unimplemented elements kinds fall back to a runtime call.
  Label* unimplemented_elements_kind = slow;
  EmitElementLoad(lookup_start_object, elements_kind, index,
                  is_jsarray_condition, &if_element_hole, &rebox_double,
                  &var_double_value, unimplemented_elements_kind, &if_oob, slow,
                  &direct_exit);

  BIND(&rebox_double);
  Return(AllocateHeapNumberWithValue(var_double_value.value()));

  BIND(&if_oob);
  {
    Comment("out of bounds");
    // On TypedArrays, all OOB loads (positive and negative) return undefined
    // without ever checking the prototype chain.
    GotoIf(IsJSTypedArrayInstanceType(lookup_start_object_instance_type),
           &return_undefined);
    // Positive OOB indices within elements index range are effectively the same
    // as hole loads. Larger keys and negative keys are named loads.
    if (Is64()) {
      Branch(UintPtrLessThanOrEqual(index,
                                    IntPtrConstant(JSObject::kMaxElementIndex)),
             &if_element_hole, slow);
    } else {
      Branch(IntPtrLessThan(index, IntPtrConstant(0)), slow, &if_element_hole);
    }
  }

  BIND(&if_element_hole);
  {
    Comment("found the hole");
    BranchIfPrototypesHaveNoElements(lookup_start_object_map, &return_undefined,
                                     slow);
  }

  BIND(&if_custom);
  {
    Comment("check if string");
    GotoIfNot(IsStringInstanceType(lookup_start_object_instance_type), slow);
    Comment("load string character");
    TNode<IntPtrT> length = LoadStringLengthAsWord(CAST(lookup_start_object));
    GotoIfNot(UintPtrLessThan(index, length), slow);
    TailCallBuiltin(Builtin::kStringCharAt, NoContextConstant(),
                    lookup_start_object, index);
  }

  BIND(&return_undefined);
  Return(UndefinedConstant());
}

void AccessorAssembler::GenericPropertyLoad(
    TNode<HeapObject> lookup_start_object, TNode<Map> lookup_start_object_map,
    TNode<Int32T> lookup_start_object_instance_type, const LoadICParameters* p,
    Label* slow, UseStubCache use_stub_cache) {
  DCHECK_EQ(lookup_start_object, p->lookup_start_object());
  ExitPoint direct_exit(this);

  Comment("key is unique name");
  Label if_found_on_lookup_start_object(this), if_property_dictionary(this),
      lookup_prototype_chain(this), special_receiver(this);
  TVARIABLE(Uint32T, var_details);
  TVARIABLE(Object, var_value);

  TNode<Name> name = CAST(p->name());

  // Receivers requiring non-standard accesses (interceptors, access
  // checks, strings and string wrappers) are handled in the runtime.
  GotoIf(IsSpecialReceiverInstanceType(lookup_start_object_instance_type),
         &special_receiver);

  // Check if the lookup_start_object has fast or slow properties.
  TNode<Uint32T> bitfield3 = LoadMapBitField3(lookup_start_object_map);
  GotoIf(IsSetWord32<Map::Bits3::IsDictionaryMapBit>(bitfield3),
         &if_property_dictionary);

  {
    // Try looking up the property on the lookup_start_object; if unsuccessful,
    // look for a handler in the stub cache.
    TNode<DescriptorArray> descriptors =
        LoadMapDescriptors(lookup_start_object_map);

    Label if_descriptor_found(this), try_stub_cache(this);
    TVARIABLE(IntPtrT, var_name_index);
    Label* notfound = use_stub_cache == kUseStubCache ? &try_stub_cache
                                                      : &lookup_prototype_chain;
    DescriptorLookup(name, descriptors, bitfield3, &if_descriptor_found,
                     &var_name_index, notfound);

    BIND(&if_descriptor_found);
    {
      LoadPropertyFromFastObject(lookup_start_object, lookup_start_object_map,
                                 descriptors, var_name_index.value(),
                                 &var_details, &var_value);
      Goto(&if_found_on_lookup_start_object);
    }

    if (use_stub_cache == kUseStubCache) {
      DCHECK_EQ(lookup_start_object, p->receiver_and_lookup_start_object());
      Label stub_cache(this);
      BIND(&try_stub_cache);
      // When there is no feedback vector don't use stub cache.
      GotoIfNot(IsUndefined(p->vector()), &stub_cache);
      // Fall back to the slow path for private symbols.
      Branch(IsPrivateSymbol(name), slow, &lookup_prototype_chain);

      BIND(&stub_cache);
      Comment("stub cache probe for fast property load");
      TVARIABLE(MaybeObject, var_handler);
      Label found_handler(this, &var_handler), stub_cache_miss(this);
      TryProbeStubCache(isolate()->load_stub_cache(), lookup_start_object,
                        lookup_start_object_map, name, &found_handler,
                        &var_handler, &stub_cache_miss);
      BIND(&found_handler);
      {
        LazyLoadICParameters lazy_p(p);
        HandleLoadICHandlerCase(&lazy_p, var_handler.value(), &stub_cache_miss,
                                &direct_exit);
      }

      BIND(&stub_cache_miss);
      {
        // TODO(jkummerow): Check if the property exists on the prototype
        // chain. If it doesn't, then there's no point in missing.
        Comment("KeyedLoadGeneric_miss");
        TailCallRuntime(Runtime::kKeyedLoadIC_Miss, p->context(),
                        p->receiver_and_lookup_start_object(), name, p->slot(),
                        p->vector());
      }
    }
  }

  BIND(&if_property_dictionary);
  {
    Comment("dictionary property load");
    // We checked for LAST_CUSTOM_ELEMENTS_RECEIVER before, which rules out
    // seeing global objects here (which would need special handling).

    TVARIABLE(IntPtrT, var_name_index);
    Label dictionary_found(this, &var_name_index);
    TNode<PropertyDictionary> properties =
        CAST(LoadSlowProperties(CAST(lookup_start_object)));
    NameDictionaryLookup<PropertyDictionary>(properties, name,
                                             &dictionary_found, &var_name_index,
                                             &lookup_prototype_chain);
    BIND(&dictionary_found);
    {
      LoadPropertyFromDictionary<PropertyDictionary>(
          properties, var_name_index.value(), &var_details, &var_value);
      Goto(&if_found_on_lookup_start_object);
    }
  }

  BIND(&if_found_on_lookup_start_object);
  {
    TNode<Object> value = CallGetterIfAccessor(
        var_value.value(), lookup_start_object, var_details.value(),
        p->context(), p->receiver(), p->name(), slow);
    Return(value);
  }

  BIND(&lookup_prototype_chain);
  {
    TVARIABLE(Map, var_holder_map);
    TVARIABLE(Int32T, var_holder_instance_type);
    Label return_undefined(this), is_private_symbol(this);
    Label loop(this, {&var_holder_map, &var_holder_instance_type});

    var_holder_map = lookup_start_object_map;
    var_holder_instance_type = lookup_start_object_instance_type;
    GotoIf(IsPrivateSymbol(name), &is_private_symbol);

    Goto(&loop);
    BIND(&loop);
    {
      // Bailout if it can be an integer indexed exotic case.
      GotoIf(InstanceTypeEqual(var_holder_instance_type.value(),
                               JS_TYPED_ARRAY_TYPE),
             slow);
      TNode<HeapObject> proto = LoadMapPrototype(var_holder_map.value());
      GotoIf(TaggedEqual(proto, NullConstant()), &return_undefined);
      TNode<Map> proto_map = LoadMap(proto);
      TNode<Uint16T> proto_instance_type = LoadMapInstanceType(proto_map);
      var_holder_map = proto_map;
      var_holder_instance_type = proto_instance_type;
      Label next_proto(this), return_value(this, &var_value), goto_slow(this);
      TryGetOwnProperty(p->context(), p->receiver(), CAST(proto), proto_map,
                        proto_instance_type, name, &return_value, &var_value,
                        &next_proto, &goto_slow);

      // This trampoline and the next are required to appease Turbofan's
      // variable merging.
      BIND(&next_proto);
      Goto(&loop);

      BIND(&goto_slow);
      Goto(slow);

      BIND(&return_value);
      Return(var_value.value());
    }

    BIND(&is_private_symbol);
    {
      CSA_DCHECK(this, IsPrivateSymbol(name));

      // For private names that don't exist on the receiver, we bail
      // to the runtime to throw. For private symbols, we just return
      // undefined.
      Branch(IsPrivateName(CAST(name)), slow, &return_undefined);
    }

    BIND(&return_undefined);
    Return(UndefinedConstant());
  }

  BIND(&special_receiver);
  {
    // TODO(ishell): Consider supporting WasmObjects.
    // TODO(jkummerow): Consider supporting JSModuleNamespace.
    GotoIfNot(
        InstanceTypeEqual(lookup_start_object_instance_type, JS_PROXY_TYPE),
        slow);

    // Private field/symbol lookup is not supported.
    GotoIf(IsPrivateSymbol(name), slow);

    direct_exit.ReturnCallBuiltin(Builtin::kProxyGetProperty, p->context(),
                                  lookup_start_object, name, p->receiver(),
                                  SmiConstant(OnNonExistent::kReturnUndefined));
  }
}

//////////////////// Stub cache access helpers.

enum AccessorAssembler::StubCacheTable : int {
  kPrimary = static_cast<int>(StubCache::kPrimary),
  kSecondary = static_cast<int>(StubCache::kSecondary)
};

TNode<IntPtrT> AccessorAssembler::StubCachePrimaryOffset(TNode<Name> name,
                                                         TNode<Map> map) {
  // Compute the hash of the name (use entire hash field).
  TNode<Uint32T> raw_hash_field = LoadNameRawHash(name);
  CSA_DCHECK(this,
             Word32Equal(Word32And(raw_hash_field,
                                   Int32Constant(Name::kHashNotComputedMask)),
                         Int32Constant(0)));

  // Using only the low bits in 64-bit mode is unlikely to increase the
  // risk of collision even if the heap is spread over an area larger than
  // 4Gb (and not at all if it isn't).
  TNode<IntPtrT> map_word = BitcastTaggedToWord(map);

  TNode<Int32T> map32 = TruncateIntPtrToInt32(UncheckedCast<IntPtrT>(
      WordXor(map_word, WordShr(map_word, StubCache::kPrimaryTableBits))));
  // Base the offset on a simple combination of name and map.
  TNode<Word32T> hash = Int32Add(raw_hash_field, map32);
  uint32_t mask = (StubCache::kPrimaryTableSize - 1)
                  << StubCache::kCacheIndexShift;
  TNode<UintPtrT> result =
      ChangeUint32ToWord(Word32And(hash, Int32Constant(mask)));
  return Signed(result);
}

TNode<IntPtrT> AccessorAssembler::StubCacheSecondaryOffset(TNode<Name> name,
                                                           TNode<Map> map) {
  // See v8::internal::StubCache::SecondaryOffset().

  // Use the seed from the primary cache in the secondary cache.
  TNode<Int32T> name32 = TruncateIntPtrToInt32(BitcastTaggedToWord(name));
  TNode<Int32T> map32 = TruncateIntPtrToInt32(BitcastTaggedToWord(map));
  // Base the offset on a simple combination of name and map.
  TNode<Word32T> hash_a = Int32Add(map32, name32);
  TNode<Word32T> hash_b = Word32Shr(hash_a, StubCache::kSecondaryTableBits);
  TNode<Word32T> hash = Int32Add(hash_a, hash_b);
  int32_t mask = (StubCache::kSecondaryTableSize - 1)
                 << StubCache::kCacheIndexShift;
  TNode<UintPtrT> result =
      ChangeUint32ToWord(Word32And(hash, Int32Constant(mask)));
  return Signed(result);
}

void AccessorAssembler::TryProbeStubCacheTable(
    StubCache* stub_cache, StubCacheTable table_id, TNode<IntPtrT> entry_offset,
    TNode<Object> name, TNode<Map> map, Label* if_handler,
    TVariable<MaybeObject>* var_handler, Label* if_miss) {
  StubCache::Table table = static_cast<StubCache::Table>(table_id);
  // The {table_offset} holds the entry offset times four (due to masking
  // and shifting optimizations).
  const int kMultiplier =
      sizeof(StubCache::Entry) >> StubCache::kCacheIndexShift;
  entry_offset = IntPtrMul(entry_offset, IntPtrConstant(kMultiplier));

  TNode<ExternalReference> key_base = ExternalConstant(
      ExternalReference::Create(stub_cache->key_reference(table)));

  // Check that the key in the entry matches the name.
  DCHECK_EQ(0, offsetof(StubCache::Entry, key));
  TNode<HeapObject> cached_key =
      CAST(Load(MachineType::TaggedPointer(), key_base, entry_offset));
  GotoIf(TaggedNotEqual(name, cached_key), if_miss);

  // Check that the map in the entry matches.
  TNode<Object> cached_map = Load<Object>(
      key_base,
      IntPtrAdd(entry_offset, IntPtrConstant(offsetof(StubCache::Entry, map))));
  GotoIf(TaggedNotEqual(map, cached_map), if_miss);

  TNode<MaybeObject> handler = ReinterpretCast<MaybeObject>(
      Load(MachineType::AnyTagged(), key_base,
           IntPtrAdd(entry_offset,
                     IntPtrConstant(offsetof(StubCache::Entry, value)))));

  // We found the handler.
  *var_handler = handler;
  Goto(if_handler);
}

void AccessorAssembler::TryProbeStubCache(StubCache* stub_cache,
                                          TNode<Object> lookup_start_object,
                                          TNode<Map> lookup_start_object_map,
                                          TNode<Name> name, Label* if_handler,
                                          TVariable<MaybeObject>* var_handler,
                                          Label* if_miss) {
  Label try_secondary(this), miss(this);

  Counters* counters = isolate()->counters();
  IncrementCounter(counters->megamorphic_stub_cache_probes(), 1);

  // Probe the primary table.
  TNode<IntPtrT> primary_offset =
      StubCachePrimaryOffset(name, lookup_start_object_map);
  TryProbeStubCacheTable(stub_cache, kPrimary, primary_offset, name,
                         lookup_start_object_map, if_handler, var_handler,
                         &try_secondary);

  BIND(&try_secondary);
  {
    // Probe the secondary table.
    TNode<IntPtrT> secondary_offset =
        StubCacheSecondaryOffset(name, lookup_start_object_map);
    TryProbeStubCacheTable(stub_cache, kSecondary, secondary_offset, name,
                           lookup_start_object_map, if_handler, var_handler,
                           &miss);
  }

  BIND(&miss);
  {
    IncrementCounter(counters->megamorphic_stub_cache_misses(), 1);
    Goto(if_miss);
  }
}

//////////////////// Entry points into private implementation (one per stub).

void AccessorAssembler::LoadIC_BytecodeHandler(const LazyLoadICParameters* p,
                                               ExitPoint* exit_point) {
  // Must be kept in sync with LoadIC.

  // This function is hand-tuned to omit frame construction for common cases,
  // e.g.: monomorphic field and constant loads through smi handlers.
  // Polymorphic ICs with a hit in the first two entries also omit frames.
  // TODO(jgruber): Frame omission is fragile and can be affected by minor
  // changes in control flow and logic. We currently have no way of ensuring
  // that no frame is constructed, so it's easy to break this optimization by
  // accident.
  Label stub_call(this, Label::kDeferred), miss(this, Label::kDeferred),
      no_feedback(this, Label::kDeferred);

  GotoIf(IsUndefined(p->vector()), &no_feedback);

  TNode<Map> lookup_start_object_map =
      LoadReceiverMap(p->receiver_and_lookup_start_object());

  // Inlined fast path.
  {
    Comment("LoadIC_BytecodeHandler_fast");

    TVARIABLE(MaybeObject, var_handler);
    Label try_polymorphic(this), if_handler(this, &var_handler);

    TNode<HeapObjectReference> weak_lookup_start_object_map =
        MakeWeak(lookup_start_object_map);
    TNode<HeapObjectReference> feedback = TryMonomorphicCase(
        p->slot(), CAST(p->vector()), weak_lookup_start_object_map, &if_handler,
        &var_handler, &try_polymorphic);

    BIND(&if_handler);
    HandleLoadICHandlerCase(p, var_handler.value(), &miss, exit_point);

    BIND(&try_polymorphic);
    {
      TNode<HeapObject> strong_feedback =
          GetHeapObjectIfStrong(feedback, &miss);
      GotoIfNot(IsWeakFixedArrayMap(LoadMap(strong_feedback)), &stub_call);
      HandlePolymorphicCase(weak_lookup_start_object_map, CAST(strong_feedback),
                            &if_handler, &var_handler, &miss);
    }
  }

  BIND(&stub_call);
  {
    Comment("LoadIC_BytecodeHandler_noninlined");

    // Call into the stub that implements the non-inlined parts of LoadIC.
    exit_point->ReturnCallBuiltin(Builtin::kLoadIC_Noninlined, p->context(),
                                  p->receiver_and_lookup_start_object(),
                                  p->name(), p->slot(), p->vector());
  }

  BIND(&no_feedback);
  {
    Comment("LoadIC_BytecodeHandler_nofeedback");
    // Call into the stub that implements the non-inlined parts of LoadIC.
    exit_point->ReturnCallBuiltin(Builtin::kLoadIC_NoFeedback, p->context(),
                                  p->receiver(), p->name(),
                                  SmiConstant(FeedbackSlotKind::kLoadProperty));
  }

  BIND(&miss);
  {
    Comment("LoadIC_BytecodeHandler_miss");

    exit_point->ReturnCallRuntime(Runtime::kLoadIC_Miss, p->context(),
                                  p->receiver(), p->name(), p->slot(),
                                  p->vector());
  }
}

void AccessorAssembler::LoadIC(const LoadICParameters* p) {
  // Must be kept in sync with LoadIC_BytecodeHandler.

  ExitPoint direct_exit(this);

  TVARIABLE(MaybeObject, var_handler);
  Label if_handler(this, &var_handler), non_inlined(this, Label::kDeferred),
      try_polymorphic(this), miss(this, Label::kDeferred),
      no_feedback(this, Label::kDeferred);

  TNode<Map> lookup_start_object_map =
      LoadReceiverMap(p->receiver_and_lookup_start_object());

  GotoIf(IsUndefined(p->vector()), &no_feedback);

  // Check monomorphic case.
  TNode<HeapObjectReference> weak_lookup_start_object_map =
      MakeWeak(lookup_start_object_map);
  TNode<HeapObjectReference> feedback = TryMonomorphicCase(
      p->slot(), CAST(p->vector()), weak_lookup_start_object_map, &if_handler,
      &var_handler, &try_polymorphic);
  BIND(&if_handler);
  {
    LazyLoadICParameters lazy_p(p);
    HandleLoadICHandlerCase(&lazy_p, var_handler.value(), &miss, &direct_exit);
  }

  BIND(&try_polymorphic);
  TNode<HeapObject> strong_feedback = GetHeapObjectIfStrong(feedback, &miss);
  {
    // Check polymorphic case.
    Comment("LoadIC_try_polymorphic");
    GotoIfNot(IsWeakFixedArrayMap(LoadMap(strong_feedback)), &non_inlined);
    HandlePolymorphicCase(weak_lookup_start_object_map, CAST(strong_feedback),
                          &if_handler, &var_handler, &miss);
  }

  BIND(&non_inlined);
  {
    LoadIC_Noninlined(p, lookup_start_object_map, strong_feedback, &var_handler,
                      &if_handler, &miss, &direct_exit);
  }

  BIND(&no_feedback);
  {
    Comment("LoadIC_nofeedback");
    // Call into the stub that implements the non-inlined parts of LoadIC.
    direct_exit.ReturnCallBuiltin(Builtin::kLoadIC_NoFeedback, p->context(),
                                  p->receiver(), p->name(),
                                  SmiConstant(FeedbackSlotKind::kLoadProperty));
  }

  BIND(&miss);
  direct_exit.ReturnCallRuntime(Runtime::kLoadIC_Miss, p->context(),
                                p->receiver_and_lookup_start_object(),
                                p->name(), p->slot(), p->vector());
}

void AccessorAssembler::LoadSuperIC(const LoadICParameters* p) {
  ExitPoint direct_exit(this);

  TVARIABLE(MaybeObject, var_handler);
  Label if_handler(this, &var_handler), no_feedback(this),
      non_inlined(this, Label::kDeferred), try_polymorphic(this),
      miss(this, Label::kDeferred);

  GotoIf(IsUndefined(p->vector()), &no_feedback);

  // The lookup start object cannot be a SMI, since it's the home object's
  // prototype, and it's not possible to set SMIs as prototypes.
  TNode<Map> lookup_start_object_map = LoadMap(CAST(p->lookup_start_object()));
  GotoIf(IsDeprecatedMap(lookup_start_object_map), &miss);

  TNode<HeapObjectReference> weak_lookup_start_object_map =
      MakeWeak(lookup_start_object_map);
  TNode<HeapObjectReference> feedback = TryMonomorphicCase(
      p->slot(), CAST(p->vector()), weak_lookup_start_object_map, &if_handler,
      &var_handler, &try_polymorphic);

  BIND(&if_handler);
  {
    LazyLoadICParameters lazy_p(p);
    HandleLoadICHandlerCase(&lazy_p, var_handler.value(), &miss, &direct_exit);
  }

  BIND(&no_feedback);
  { LoadSuperIC_NoFeedback(p); }

  BIND(&try_polymorphic);
  TNode<HeapObject> strong_feedback = GetHeapObjectIfStrong(feedback, &miss);
  {
    Comment("LoadSuperIC_try_polymorphic");
    GotoIfNot(IsWeakFixedArrayMap(LoadMap(strong_feedback)), &non_inlined);
    HandlePolymorphicCase(weak_lookup_start_object_map, CAST(strong_feedback),
                          &if_handler, &var_handler, &miss);
  }

  BIND(&non_inlined);
  {
    // LoadIC_Noninlined can be used here, since it handles the
    // lookup_start_object != receiver case gracefully.
    LoadIC_Noninlined(p, lookup_start_object_map, strong_feedback, &var_handler,
                      &if_handler, &miss, &direct_exit);
  }

  BIND(&miss);
  direct_exit.ReturnCallRuntime(Runtime::kLoadWithReceiverIC_Miss, p->context(),
                                p->receiver(), p->lookup_start_object(),
                                p->name(), p->slot(), p->vector());
}

void AccessorAssembler::LoadIC_Noninlined(const LoadICParameters* p,
                                          TNode<Map> lookup_start_object_map,
                                          TNode<HeapObject> feedback,
                                          TVariable<MaybeObject>* var_handler,
                                          Label* if_handler, Label* miss,
                                          ExitPoint* exit_point) {
  // Not monomorphic -- this cases is handled in the bytecode handler.
  CSA_DCHECK(this, TaggedNotEqual(lookup_start_object_map, feedback));
  CSA_DCHECK(this, Word32BinaryNot(IsWeakFixedArrayMap(LoadMap(feedback))));
  DCHECK_EQ(MachineRepresentation::kTagged, var_handler->rep());

  {
    Label try_megamorphic(this), try_megadom(this);
    GotoIf(TaggedEqual(feedback, MegamorphicSymbolConstant()),
```