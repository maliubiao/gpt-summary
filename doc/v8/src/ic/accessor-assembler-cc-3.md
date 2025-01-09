Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/ic/accessor-assembler.cc`.

Here's a breakdown of the thought process to analyze the code and address the user's request:

1. **Identify the Core Functionality:** The code primarily deals with loading properties from JavaScript objects, specifically focusing on different object types and optimization techniques. Keywords like "Load", "Element", "Property", "Cache", "TypedArray", "Dictionary" are strong indicators.

2. **Analyze Key Code Blocks:**
    * **`EmitElementLoad`:**  This function seems responsible for loading elements based on the `elements_kind` of the object. It handles various cases like fast elements, holes, out-of-bounds access, typed arrays, and dictionary elements.
    * **Typed Array Handling:**  The code has distinct blocks for different typed array element kinds (uint8, int32, float64, bigint, etc.). This suggests handling of efficient data access in typed arrays. It also includes checks for detached buffers.
    * **Dictionary Handling:**  A separate section deals with `DICTIONARY_ELEMENTS`, which are used for sparse arrays or objects with many properties.
    * **Stub Cache:**  Functions like `StubCachePrimaryOffset`, `StubCacheSecondaryOffset`, and `TryProbeStubCache` indicate an optimization mechanism to cache property access information for faster lookups.
    * **LoadIC Handlers:**  The `LoadIC_BytecodeHandler` and `LoadIC` functions suggest the implementation of inline caching (IC), a key optimization in JavaScript engines. They handle different IC states (monomorphic, polymorphic, megamorphic).
    * **Prototype Chain Lookup:**  The `GenericPropertyLoad` function includes logic to traverse the prototype chain if a property is not found directly on the object.

3. **Infer High-Level Functionality:** Based on the identified blocks, the primary goal of `accessor-assembler.cc` is to implement optimized mechanisms for loading JavaScript object properties. This involves:
    * Fast path for common cases (e.g., direct property access).
    * Handling different object structures (e.g., arrays, typed arrays, dictionaries).
    * Utilizing inline caching to speed up repeated property accesses.
    * Falling back to slower paths or runtime calls when optimizations are not applicable or when errors occur.

4. **Address Specific User Questions:**
    * **File Extension:** The user correctly notes the `.cc` extension, indicating C++ source code, not Torque.
    * **Relationship to JavaScript:**  The code directly implements core JavaScript object property access semantics.
    * **JavaScript Examples:** Provide simple JavaScript code snippets that would trigger the different code paths within `accessor-assembler.cc`, such as accessing array elements, object properties, and typed array elements.
    * **Code Logic Reasoning:**  Choose a specific code block (like the typed array loading) and explain the assumptions, inputs (object, index), and expected outputs (value or indication of absence).
    * **Common Programming Errors:**  Relate common JavaScript errors (like accessing out-of-bounds array elements or properties on `null`/`undefined`) to how the C++ code might handle these situations.

5. **Synthesize a Summary:** Combine the key functionalities into a concise summary of the file's purpose.

6. **Review and Refine:** Ensure the explanation is clear, accurate, and addresses all parts of the user's request. Pay attention to terminology and ensure it's understandable. For example, explicitly state that `.cc` means C++ and `.tq` means Torque.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focus solely on the `EmitElementLoad` function.
* **Correction:** Realize that the scope is broader and includes property loading in general, including optimizations like the stub cache and inline caching. Expand the analysis to include `GenericPropertyLoad` and the IC-related functions.
* **Initial thought:** Provide complex JavaScript examples.
* **Correction:** Use simpler, more direct examples to illustrate the basic functionality being implemented in the C++ code.
* **Initial thought:**  Only describe the code.
* **Correction:** Explicitly address the user's questions about file extensions, JavaScript relationships, examples, logic, and common errors. This makes the answer more complete and helpful.

By following these steps, the generated explanation effectively addresses the user's request and provides a good understanding of the `accessor-assembler.cc` file's role in the V8 JavaScript engine.
这是V8 JavaScript引擎源代码文件 `v8/src/ic/accessor-assembler.cc` 的第 4 部分，总共 7 部分。从代码片段来看，这个文件主要负责实现**高效地访问 JavaScript 对象的属性和元素**。它使用了汇编器（assembler）来生成底层的机器码，以达到最佳的性能。

**功能归纳 (基于提供的代码片段):**

这部分代码主要关注**加载（load）JavaScript 对象的属性和元素**，特别是针对不同类型的对象和优化策略：

1. **处理数字索引的元素加载 (`EmitElementLoad`, `GenericElementLoad`)**:
   - 针对不同类型的元素存储方式进行优化，例如：
     - **快速元素 (Fast Elements):** 直接从对象的属性数组中加载。
     - **字典元素 (Dictionary Elements):**  在字典中查找元素。
     - **类型化数组元素 (Typed Array Elements):**  根据不同的类型（Uint8, Int32, Float64 等）从内存中加载，并处理字节序和数据转换。
     - **可共享数组缓冲区（RAB/GSAB Typed Arrays）:**  增加了对共享内存的类型化数组的处理。
   - 实现了边界检查 (bounds check) 和空洞元素 (hole) 的处理。
   - 针对类型化数组，还检查了缓冲区分离 (detached buffer) 的情况。
   - 对于超出数组边界的访问，根据对象类型采取不同的处理方式（例如，类型化数组返回 `undefined`）。

2. **处理属性加载 (`GenericPropertyLoad`)**:
   - 区分快速属性和字典属性。
   - **快速属性 (Fast Properties):**  通过描述符数组 (DescriptorArray) 查找属性信息，并直接加载属性值。
   - **字典属性 (Dictionary Properties):**  在属性字典 (PropertyDictionary) 中查找属性。
   - 实现了对访问器属性 (accessor properties) 的处理，如果属性是访问器，则调用 getter 函数。
   - 实现了原型链查找 (prototype chain lookup)，如果在当前对象上找不到属性，则会沿着原型链向上查找。
   - 使用 **Stub Cache** 进行优化，缓存了最近的属性访问信息，以加快后续的访问速度。

3. **Stub Cache 相关的操作 (`StubCachePrimaryOffset`, `StubCacheSecondaryOffset`, `TryProbeStubCacheTable`, `TryProbeStubCache`)**:
   - 实现了 Stub Cache 的探测 (probe) 逻辑，用于在缓存中查找属性访问的处理器 (handler)。
   - 计算了 Stub Cache 中主表 (primary table) 和副表 (secondary table) 的偏移量。

4. **LoadIC (Load Inline Cache) 的处理 (`LoadIC_BytecodeHandler`, `LoadIC`, `LoadSuperIC`, `LoadIC_Noninlined`)**:
   - 实现了 LoadIC 的快速路径和慢速路径。
   - **Monomorphic IC:**  针对单一类型的对象进行优化。
   - **Polymorphic IC:** 针对有限几种类型的对象进行优化。
   - **Megamorphic IC:**  处理多种类型的对象，通常会回退到更通用的处理方式。
   - 涉及到反馈向量 (feedback vector) 的使用，用于收集运行时类型信息，以便进行优化。
   - `LoadSuperIC` 专门用于处理 `super` 关键字的属性访问。

5. **原型链无效化 (`InvalidateValidityCellIfPrototype`)**:
   - 当一个 Map 对象成为一个原型对象时，可能需要使其相关的 validity cell 失效，以确保缓存的一致性。

**如果 `v8/src/ic/accessor-assembler.cc` 以 `.tq` 结尾，那它是个 v8 torque 源代码。** 但根据描述，它以 `.cc` 结尾，所以是 **C++ 源代码**。 Torque 是一种 V8 自研的类型化的中间语言，用于生成高效的汇编代码。

**与 JavaScript 功能的关系及 JavaScript 示例:**

`v8/src/ic/accessor-assembler.cc` 中的代码直接实现了 JavaScript 中属性访问的核心功能。以下是一些 JavaScript 示例，它们会触发 `accessor-assembler.cc` 中相应的逻辑：

```javascript
// 1. 访问数组元素（触发 EmitElementLoad，处理快速元素）
const arr = [1, 2, 3];
const firstElement = arr[0]; // 触发快速元素加载

// 2. 访问对象属性（触发 GenericPropertyLoad，处理快速属性）
const obj = { a: 1, b: 2 };
const propertyA = obj.a; // 触发快速属性加载

// 3. 访问字典对象属性（触发 GenericPropertyLoad，处理字典属性）
const dictObj = {};
for (let i = 0; i < 1000; i++) {
  dictObj[`key_${i}`] = i;
}
const someValue = dictObj.key_500; // 触发字典属性加载

// 4. 访问类型化数组元素（触发 EmitElementLoad，处理类型化数组元素）
const typedArray = new Uint8Array([10, 20, 30]);
const firstTypedElement = typedArray[0]; // 触发类型化数组元素加载

// 5. 访问超出数组边界的元素（触发 EmitElementLoad，处理边界检查）
const outOfBounds = arr[10]; // 结果为 undefined

// 6. 访问原型链上的属性（触发 GenericPropertyLoad，原型链查找）
const parent = { parentProp: 'parent value' };
const child = Object.create(parent);
const inheritedProp = child.parentProp; // 触发原型链查找

// 7. 使用访问器属性
const accessorObj = {
  _value: 0,
  get value() {
    return this._value;
  },
  set value(newValue) {
    this._value = newValue;
  }
};
const currentValue = accessorObj.value; // 触发调用 getter
accessorObj.value = 10; // 触发调用 setter

// 8. 多次访问同一个属性 (触发 LoadIC 的优化)
const person = { name: 'Alice' };
const name1 = person.name; // 第一次访问，可能触发 LoadIC Miss
const name2 = person.name; // 第二次访问，可能触发 Monomorphic IC Hit
const name3 = person.name; // 后续访问，可能继续保持 Monomorphic IC Hit
```

**代码逻辑推理和假设输入与输出 (以类型化数组加载为例):**

**假设输入:**

- `object`: 一个 `Uint8Array` 类型的 JavaScript 对象，例如 `new Uint8Array([10, 20, 30])`。
- `elements_kind`: 代表元素类型的枚举值，对于 `Uint8Array` 是 `UINT8_ELEMENTS`。
- `index`:  要访问的元素的索引，例如 `0`。
- `access_mode`:  `LoadAccessMode::kLoad` (表示要加载元素的值)。

**预期输出:**

- 如果索引有效（例如 `0`），则输出对应索引上的元素值，转换为 JavaScript 的数值类型 (Smi 或 HeapNumber)，例如 `10`。
- 如果索引超出边界（例如 `10`），则跳转到 `out_of_bounds` 标签。
- 如果类型化数组的缓冲区已分离，则跳转到 `miss` 标签。

**代码逻辑推理 (针对 `UINT8_ELEMENTS` 分支):**

1. 代码会检查 `elements_kind` 是否为 `UINT8_ELEMENTS`。
2. 如果是，则计算内存中的实际地址偏移量：`index * sizeof(uint8_t)`。
3. 使用 `Load<Uint8T>` 从计算出的内存地址加载一个无符号 8 位整数。
4. 将加载的 8 位整数通过 `SmiFromInt32` 转换为 V8 的 Smi (Small Integer) 类型，并作为结果返回。

**用户常见的编程错误:**

1. **访问超出数组或类型化数组边界的元素:**
   ```javascript
   const arr = [1, 2, 3];
   console.log(arr[5]); // 输出 undefined
   const typedArray = new Uint8Array([10, 20, 30]);
   console.log(typedArray[5]); // 输出 undefined
   ```
   `accessor-assembler.cc` 中的边界检查逻辑会处理这种情况，并根据对象类型返回 `undefined` 或触发错误（在某些严格模式下或特定的操作中）。

2. **访问 `null` 或 `undefined` 的属性:**
   ```javascript
   const obj = null;
   console.log(obj.a); // TypeError: Cannot read properties of null (reading 'a')
   ```
   虽然 `accessor-assembler.cc` 本身不直接处理 `null` 或 `undefined` 的情况，但在调用到这里之前，V8 的其他部分会进行检查并抛出 `TypeError`。

3. **错误地假设对象具有某个属性:**
   ```javascript
   const obj = { a: 1 };
   console.log(obj.b); // 输出 undefined
   ```
   `accessor-assembler.cc` 中的属性查找逻辑会沿着原型链查找，如果最终找不到属性，则返回 `undefined`。

4. **在类型化数组上执行不兼容类型的操作:**
   虽然不是 `accessor-assembler.cc` 直接处理，但与类型化数组相关的操作需要注意类型匹配。

**总结 `v8/src/ic/accessor-assembler.cc` 的功能 (基于第 4 部分):**

`v8/src/ic/accessor-assembler.cc` 的第 4 部分主要负责实现 V8 引擎中**高效加载 JavaScript 对象属性和元素**的核心逻辑。它针对不同类型的对象（普通对象、数组、类型化数组、字典对象等）和不同的属性存储方式进行了优化，并利用 Stub Cache 和 LoadIC 等技术来提升属性访问的性能。这部分代码是 JavaScript 引擎性能的关键组成部分，直接影响着 JavaScript 代码的执行效率。

Prompt: 
```
这是目录为v8/src/ic/accessor-assembler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/ic/accessor-assembler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共7部分，请归纳一下它的功能

"""
e);
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
           
"""


```