Response:
My thinking process to analyze the provided C++ code snippet and fulfill the request went through these stages:

1. **Initial Understanding of the Request:** I noted that the request asked for a functional summary of a V8 C++ source file (`accessor-assembler.cc`), considering its potential Torque equivalent and JavaScript relevance. It also emphasized providing examples, reasoning about input/output, and highlighting common programming errors. The "part 3 of 7" indicates a larger context, but the focus should remain on this snippet.

2. **High-Level Code Scan:** I quickly skimmed the code to identify key elements:
    * **Class Name:** `AccessorAssembler` - This suggests it's responsible for generating code related to property access (getting and setting). The "Assembler" part indicates it likely deals with low-level code generation.
    * **Methods:** I identified various methods like `CheckFieldType`, `OverwriteExistingFastDataProperty`, `StoreJSSharedStructField`, `HandleStoreICProtoHandler`, `HandleStoreToProxy`, `HandleStoreICSmiHandlerCase`, `ExtendPropertiesBackingStore`, `EmitFastElementsBoundsCheck`, `EmitElementLoad`, and others. The names themselves give strong hints about their functionality. For example, `CheckFieldType` likely verifies the type of a value being stored in a field. `OverwriteExistingFastDataProperty` handles updating existing properties.
    * **Control Flow:** I noticed extensive use of `Goto`, `Branch`, and `Label`, common in code generation scenarios where the flow isn't strictly linear. `BIND` is used to mark the targets of these jumps.
    * **V8 Specific Types:**  Terms like `TNode`, `Map`, `HeapObject`, `DescriptorArray`, `PropertyArray`, `FixedArrayBase`, `Context`, `JSObject`, `JSProxy`, `Smi`, `Float64T`, `Uint32T`, and constants like `kAnyType`, `kNoneType`, etc., confirmed that this is indeed V8 internal code.
    * **"IC" in Method Names:**  The presence of "IC" (Inline Cache) in names like `HandleStoreICProtoHandler` and `HandleStoreICSmiHandlerCase` is a key indicator. ICs are a performance optimization technique in V8.

3. **Deeper Dive into Key Functions:** I focused on understanding the purpose of the more prominent functions:
    * **`CheckFieldType`:** This function clearly checks if a given `value` is compatible with the expected `field_type` of a property. It handles the `Any` and `None` field types and map checks.
    * **`OverwriteExistingFastDataProperty`:** This seems to be the core logic for updating existing properties in "fast" objects (objects with a fixed structure). It distinguishes between in-object properties and those stored in a separate backing store. It also handles different data representations (tagged, double).
    * **`HandleStoreICProtoHandler`:** This is a complex function dealing with storing properties, specifically considering the prototype chain. It handles various cases based on the `StoreHandler` type, including normal stores, slow stores, global proxy stores, accessor stores, and API setters. The presence of `ICMode` reinforces its IC-related nature.
    * **`HandleStoreToProxy`:** This function handles property stores on `JSProxy` objects, which have special semantics.
    * **`HandleStoreICSmiHandlerCase`:** This function deals with stores when the IC handler indicates a simple field store. It handles different representations (tagged, heap object, Smi, double) and performs type checks.
    * **`ExtendPropertiesBackingStore`:** This handles the case where a fast object needs to grow its property storage.
    * **`EmitFastElementsBoundsCheck` and `EmitElementLoad`:** These functions are crucial for handling access to array elements, performing bounds checks and loading elements based on the array's element kind (packed, holey, double, etc.).

4. **Relating to JavaScript:**  I thought about how these C++ functions manifest in JavaScript behavior. Property access (`object.property = value`, `object.property`) is the obvious connection. The distinction between fast and slow properties relates to how V8 optimizes object layout and access. Proxies have explicit JavaScript syntax. Array element access (`array[index]`) directly corresponds to the `EmitElementLoad` functionality.

5. **Considering Torque:** The request specifically asked about `.tq` files (Torque). Based on my understanding of Torque as V8's domain-specific language for generating assembly code, I recognized that many of these C++ functions likely have corresponding Torque implementations or are called from Torque-generated code. The low-level nature of the operations (field access, type checks) aligns well with Torque's purpose.

6. **Crafting Examples and Explanations:**  With the functional understanding in place, I started constructing the requested elements:
    * **Functionality Summary:** I summarized the core responsibilities of the file.
    * **Torque Connection:** I stated the likelihood of a Torque equivalent.
    * **JavaScript Examples:** I created simple JavaScript snippets that would trigger the underlying C++ logic (e.g., setting properties, accessing array elements, using proxies).
    * **Input/Output Reasoning:** I chose key functions (`CheckFieldType`, `OverwriteExistingFastDataProperty`) and described potential input scenarios and the expected outcomes.
    * **Common Programming Errors:** I considered errors that relate to the code's functionality, such as type mismatches when setting properties and out-of-bounds array accesses.

7. **Structuring the Output:** I organized the information according to the request's structure (functionality, Torque, JavaScript examples, reasoning, errors, summary). I used clear headings and formatting to improve readability.

8. **Review and Refinement:**  I reread my analysis to ensure accuracy, clarity, and completeness, addressing all aspects of the request. I made sure the JavaScript examples were relevant and the reasoning was sound. I also paid attention to the "part 3 of 7" prompt and ensured the summary focused on the provided snippet's function within the larger context of property access.

This iterative process of scanning, understanding, connecting to JavaScript and Torque, and then elaborating with examples and reasoning allowed me to generate a comprehensive response to the prompt.
这是对 V8 源代码文件 `v8/src/ic/accessor-assembler.cc` 的功能进行归纳的第三部分。基于你提供的代码片段，我们可以继续分析 `AccessorAssembler` 的功能。

**已分析功能回顾 (基于前两部分):**

1. **辅助生成高效的属性访问代码:** `AccessorAssembler` 提供了一系列用于生成机器码的工具函数，这些函数用于实现 V8 中对象属性的快速读取和写入 (LoadIC 和 StoreIC)。
2. **处理不同类型的属性:** 它能够处理各种类型的属性，包括数据属性、访问器属性以及原型链上的属性。
3. **类型检查和转换:**  提供了类型检查和转换的机制，确保在属性访问时数据的类型安全。
4. **内联缓存 (IC) 的支持:**  `AccessorAssembler` 是实现内联缓存的关键部分，用于优化重复的属性访问操作。
5. **处理慢速属性:** 当快速路径无法执行时，会回退到慢速路径进行处理。

**本部分代码的功能归纳:**

本部分代码延续了 `AccessorAssembler` 处理属性写入操作的功能，并深入探讨了以下几个关键方面：

6. **字段类型检查和覆写:**
   - `CheckFieldType`:  此函数用于检查尝试写入的值是否与属性的字段类型兼容。它会检查字段类型是否为 `Any` (可以接受任何值) 或者是一个特定的 Map (表示期望的对象类型)。
   - `OverwriteExistingFastDataProperty`: 这个函数负责覆写已经存在的快速数据属性。它会根据属性的位置 (在对象自身或在扩展属性数组中) 和表示方式 (Tagged, Double) 来执行相应的存储操作。同时，它会处理常量属性的写入，如果尝试写入常量属性，则会跳转到 `slow` 标签 (表示需要进行更复杂的处理)。

7. **共享结构体字段的存储:**
   - `StoreJSSharedStructField`:  这个函数专门用于存储 `JSSharedStruct` 对象的字段。它与普通的 `JSObject` 类似，但需要处理共享内存的特性，使用 `SharedValueBarrier` 来确保跨线程的可见性。

8. **原型链有效性检查:**
   - `CheckPrototypeValidityCell`:  用于检查原型链的有效性。它会检查一个 `maybe_validity_cell` 是否指示原型链有效，如果不是，则会加载 `Cell` 的值并进行进一步检查。

9. **处理 StoreIC 的原型处理器:**
   - `HandleStoreICProtoHandler`:  这是一个非常重要的函数，用于处理 StoreIC 过程中涉及到原型链的情况。它会根据 `StoreHandler` 的类型采取不同的操作，包括：
     - **查找起始对象上的属性:** 如果属性在原型链的起始对象上找到，并且是可写的数据属性，则直接写入值。
     - **处理不同的处理器类型:** 它能处理 `kNormal` (添加到字典模式对象), `kSlow`, `kGlobalProxy`, `kAccessorFromPrototype` (调用 setter), `kNativeDataProperty`, `kApiSetter` 等多种 `StoreHandler` 类型。
     - **处理全局代理对象的存储:** 使用 `StoreGlobalIC_PropertyCellCase` 处理全局代理对象的属性存储。

10. **处理 Proxy 对象的存储:**
    - `HandleStoreToProxy`:  专门处理向 `JSProxy` 对象存储属性的情况。它会调用内置的 `ProxySetProperty` 函数。

11. **处理 Smi 处理器的情况:**
    - `HandleStoreICSmiHandlerCase`:  当 StoreIC 的处理器是 Smi 类型时 (通常表示一个快速字段存储)，此函数会根据字段的表示方式 (Tagged, HeapObject, Smi, Double) 执行相应的存储操作，并进行必要的类型检查。

12. **辅助检查函数:**
    - `CheckHeapObjectTypeMatchesDescriptor`: 检查尝试写入的堆对象类型是否与描述符中定义的类型匹配。
    - `CheckDescriptorConsidersNumbersMutable`: 检查描述符是否允许修改数字类型的属性。
    - `GotoIfNotSameNumberBitPattern`: 用于比较两个 `Float64T` 的位模式是否相同，用于精确的数字比较。
    - `HandleStoreFieldAndReturn`: 执行实际的字段存储操作，包括对象内字段和扩展属性数组中的字段，并处理常量字段的情况。

13. **扩展属性存储:**
    - `ExtendPropertiesBackingStore`: 当需要向对象添加更多属性，且对象的现有属性存储空间不足时，此函数会扩展属性数组的容量。

14. **快速元素边界检查和加载:**
    - `EmitFastElementsBoundsCheck`:  在访问快速元素类型的数组时，执行边界检查，确保索引在有效范围内。
    - `EmitElementLoad`:  根据元素的类型 (packed, holey, double 等) 加载数组元素。

**与 JavaScript 的关系:**

本部分的代码直接关系到 JavaScript 中属性赋值操作的行为，例如：

```javascript
const obj = { a: 1 };
obj.a = 2; // OverwriteExistingFastDataProperty 可能被调用

const shared = new SharedArrayBuffer(8);
const sharedObj = { b: new Int32Array(shared) };
sharedObj.b[0] = 5; // StoreJSSharedStructField 可能被调用

function Parent() {}
function Child() {}
Child.prototype = new Parent();
const child = new Child();
child.c = 3; // HandleStoreICProtoHandler 在处理原型链上的存储时会被调用

const proxy = new Proxy({}, { set: function(target, prop, value) { ... } });
proxy.d = 4; // HandleStoreToProxy 会被调用

const arr = [1.1, 2.2];
arr[0] = 3.3; // EmitElementLoad 会被调用
```

**代码逻辑推理 (假设输入与输出):**

**假设输入 `OverwriteExistingFastDataProperty`:**

- `object`: 一个具有快速属性的对象 `{ a: 1 }`。
- `object_map`: `object` 的 Map 对象。
- `descriptors`: `object` 的描述符数组，包含属性 `a` 的信息。
- `descriptor_name_index`: 属性 `a` 在描述符数组中的索引。
- `details`: 属性 `a` 的详细信息，例如位置和表示方式。
- `value`: 要写入的新值，例如数字 `2`。
- `slow`: 一个标签，如果需要回退到慢速路径则跳转到此。
- `do_transitioning_store`: `false` (假设不是转换存储)。

**预期输出:**

- 如果属性 `a` 是可写的，且类型兼容，则 `object.a` 的值会被更新为 `2`，并且执行会跳转到 `done` 标签。
- 如果属性 `a` 是常量，则会跳转到 `slow` 标签。
- 如果 `value` 的类型与属性 `a` 的字段类型不匹配，则会跳转到 `slow` 标签。

**用户常见的编程错误:**

1. **类型不匹配:** 尝试将错误类型的值赋给具有类型限制的属性。例如，如果一个属性被优化为存储数字，却尝试赋给字符串。`CheckFieldType` 会捕获这类错误。

   ```javascript
   const obj = { a: 1 }; // 假设 'a' 被优化为存储数字
   obj.a = "hello"; // 可能导致类型检查失败，回退到慢速路径
   ```

2. **尝试修改常量属性:**  尝试修改使用 `const` 或在对象定义时标记为只读的属性。`IsPropertyDetailsConst` 会检测这种情况。

   ```javascript
   const obj = { a: 1 };
   Object.defineProperty(obj, 'b', { value: 2, writable: false });
   obj.a = 3; // 可以修改
   obj.b = 4; // 尝试修改常量属性，在严格模式下会报错，非严格模式下会静默失败
   ```

3. **访问不存在或超出范围的数组元素:**  在快速元素数组中访问超出索引范围的元素。`EmitFastElementsBoundsCheck` 会检测这类错误。

   ```javascript
   const arr = [1, 2, 3];
   arr[5] = 4; // 尝试访问超出范围的索引
   ```

**功能归纳:**

`v8/src/ic/accessor-assembler.cc` (本部分) 的核心功能是提供用于生成高效机器码的工具，以实现 JavaScript 对象属性的写入操作。它深入处理了各种复杂情况，包括：

- **类型安全的属性写入:** 确保写入的值与属性的预期类型一致。
- **不同类型的属性存储:**  处理普通数据属性、共享结构体属性以及常量属性的存储。
- **原型链的处理:**  在原型链查找和写入属性时进行优化。
- **Proxy 对象的支持:**  处理对 Proxy 对象的属性赋值。
- **快速数组元素的写入:**  提供快速访问和修改数组元素的能力。

总而言之，这部分代码是 V8 引擎中实现高性能属性写入的关键组成部分，它通过生成高度优化的机器码来加速 JavaScript 代码的执行。它通过细致的类型检查和对不同属性类型的处理，保证了 JavaScript 语义的正确性，并尽可能地利用快速路径来提升性能。

Prompt: 
```
这是目录为v8/src/ic/accessor-assembler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/ic/accessor-assembler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共7部分，请归纳一下它的功能

"""
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
          LoadFixedDoubleArrayElement(CAST(elements), intptr_index, if_hol
"""


```