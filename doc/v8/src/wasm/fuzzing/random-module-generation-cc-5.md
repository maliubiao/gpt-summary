Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/wasm/fuzzing/random-module-generation.cc`. The request includes several specific constraints:

1. **List the functionality:** Describe what the code does.
2. **Torque check:** Verify if the file ends with `.tq`.
3. **JavaScript relation:** If the code relates to JavaScript, provide an example.
4. **Logic inference:**  If there's code logic, give example inputs and outputs.
5. **Common errors:** If it relates to common programming errors, illustrate with examples.
6. **Part of a series:** Acknowledge that this is part 6 of 7 and summarize the function's role within the larger context.

Let's break down the code snippet:

- It defines a function `GenerateInitExpr`.
- This function appears to recursively generate WebAssembly initialization expressions (`WasmInitExpr`).
- The generation depends on the desired value type (`type`) and uses a `DataRange` for random choices.
- It handles different WebAssembly value types (`kI32`, `kI64`, `kF32`, `kF64`, `kS128`, `kRefNull`, `kRef`).
- For `kRef`, it handles different heap types (`kStruct`, `kAny`, `kEq`, `kFunc`, `kExtern`, `kI31`, `kArray`).
- It seems to use a `WasmModuleBuilder` to access information about the module being built (e.g., global types, function declarations).
- It uses recursion with a maximum depth to avoid infinite loops.

**Plan:**

1. **Functionality:** Explain that `GenerateInitExpr` randomly generates WebAssembly initialization expressions for global variables, tables, and element segments. It handles various value types and uses recursion to build complex expressions.
2. **Torque:** Check the filename suffix. It's `.cc`, so it's not a Torque file.
3. **JavaScript:** Explain the connection to JavaScript through WebAssembly's role as a compilation target. Give a JavaScript example of creating a WebAssembly module with a global variable that uses an initializer expression.
4. **Logic Inference:** Choose a simple case, like generating an `i32` initializer. Show how different random choices in `DataRange` can lead to different outputs (constant, binary operation).
5. **Common Errors:**  Explain that incorrect handling of recursive structures in init expressions can lead to stack overflows. Give a conceptual example (not actual C++ code).
6. **Summary:**  Knowing it's part 6/7, infer that the earlier parts likely focus on other aspects of random WebAssembly module generation (e.g., function bodies, type definitions) and the later part probably finalizes the module. Emphasize that this part focuses on *initialization expressions*.
这是对 V8 源代码文件 `v8/src/wasm/fuzzing/random-module-generation.cc` 中 `GenerateInitExpr` 函数的分析。

**功能列举:**

`GenerateInitExpr` 函数的主要功能是**随机生成 WebAssembly 模块中全局变量、表元素或者段的初始化表达式 (initializer expressions)**。更具体地说，它根据给定的类型 ( `type` )，利用随机数据源 ( `range` ) 和模块构建器 ( `builder` )，生成一个 `WasmInitExpr` 对象。这个函数能够处理多种 WebAssembly 值类型，包括：

* **数值类型:** `i32`, `i64`, `f32`, `f64`
* **SIMD 类型:** `s128`
* **引用类型:** `ref null`, `ref` (包括各种堆类型如 `struct`, `array`, `func`, `extern`, `i31`, 以及自定义类型)

该函数通过递归调用自身来生成更复杂的初始化表达式，例如二元运算。它还考虑了已经存在的全局变量，并尝试复用不可变的全局变量作为初始化表达式的一部分。

**Torque 源代码检查:**

`v8/src/wasm/fuzzing/random-module-generation.cc` 以 `.cc` 结尾，因此它不是一个 V8 Torque 源代码文件。V8 Torque 源代码文件通常以 `.tq` 结尾。

**与 JavaScript 的关系:**

WebAssembly 模块通常由 JavaScript 加载和实例化。全局变量的初始化表达式在模块实例化时执行，这直接影响了 JavaScript 可以访问到的 WebAssembly 实例的状态。

**JavaScript 示例:**

假设 `GenerateInitExpr` 生成了一个初始化表达式，用于初始化一个 `i32` 类型的全局变量，其值为 `10 + 5`。在生成的 WebAssembly 模块中，它可能看起来像这样 (以 WAT 格式表示):

```wat
(module
  (global (mut i32) (i32.add (i32.const 10) (i32.const 5)))
  (export "my_global" (global 0))
)
```

在 JavaScript 中，你可以加载和访问这个全局变量：

```javascript
async function loadWasm() {
  const response = await fetch('your_module.wasm'); // 假设你的 wasm 文件名为 your_module.wasm
  const buffer = await response.arrayBuffer();
  const module = await WebAssembly.compile(buffer);
  const instance = await WebAssembly.instantiate(module);
  console.log(instance.exports.my_global.value); // 输出: 15
}

loadWasm();
```

在这个例子中，WebAssembly 模块中的全局变量 `my_global` 的初始值是由 `GenerateInitExpr` 生成的表达式 `10 + 5` 计算出来的。当 JavaScript 代码访问 `instance.exports.my_global.value` 时，它会得到初始化后的值 `15`。

**代码逻辑推理 (假设输入与输出):**

**假设输入:**

* `zone`: 一个内存分配区域。
* `range`: 一个提供随机数据的对象，当前位置提供的值为 0。
* `builder`: 一个 `WasmModuleBuilder` 对象，当前没有已声明的不可变 `i32` 全局变量。
* `type`:  `kWasmI32` (表示 32 位整数类型)。
* `structs`: 一个空的 `ModuleTypeIndex` 向量。
* `arrays`: 一个空的 `ModuleTypeIndex` 向量。
* `recursion_depth`: 0。

**预期输出:**

根据代码逻辑，当 `type` 为 `kWasmI32` 时，并且 `range.get<uint8_t>() % 5` 的结果为 0, 1 或 2 时，会生成一个常量。由于 `range` 当前位置的值为 0，假设 `range.get<uint8_t>()` 返回 0，那么 `0 % 5` 的结果为 0。因此，函数会返回一个包含从 `range` 中获取的 `int32_t` 值的 `WasmInitExpr`。

```c++
// 假设 range.get<int32_t>() 返回 123
return WasmInitExpr(range.get<int32_t>()); // 输出: WasmInitExpr(123)
```

**假设输入 (另一种情况):**

* `zone`: 一个内存分配区域。
* `range`: 一个提供随机数据的对象，当前位置提供的值为 3。
* `builder`: 一个 `WasmModuleBuilder` 对象。
* `type`:  `kWasmI32`.
* `structs`: 空。
* `arrays`: 空。
* `recursion_depth`: 0。

**预期输出:**

如果 `range.get<uint8_t>() % 5` 的结果为 3，那么函数会生成一个二元加法运算的初始化表达式。这将递归调用 `GenerateInitExpr` 两次来生成操作数。

```c++
// 假设递归调用分别生成 WasmInitExpr(4) 和 WasmInitExpr(5)
return WasmInitExpr::Binop(
    zone, WasmInitExpr::kI32Add,
    GenerateInitExpr(zone, range, builder, kWasmI32, structs, arrays, 1), // 假设返回 WasmInitExpr(4)
    GenerateInitExpr(zone, range, builder, kWasmI32, structs, arrays, 1)); // 假设返回 WasmInitExpr(5)
// 输出: WasmInitExpr::Binop(zone, WasmInitExpr::kI32Add, WasmInitExpr(4), WasmInitExpr(5))
```

**涉及用户常见的编程错误:**

虽然这个 C++ 代码本身不容易直接导致用户在编写 JavaScript 或 WebAssembly 时犯错，但其生成的内容可能会暴露一些与初始化相关的常见错误：

1. **循环依赖:** 如果 `GenerateInitExpr` 生成的初始化表达式之间存在循环依赖（例如，全局变量 A 的初始化依赖于全局变量 B，而 B 的初始化又依赖于 A），WebAssembly 虚拟机在实例化模块时会抛出错误。

   **例子 (概念性):**

   ```wat
   (module
     (global $a (mut i32) (global.get $b)) ;; A 依赖 B
     (global $b (mut i32) (global.get $a)) ;; B 依赖 A
     (export "a" (global $a))
     (export "b" (global $b))
   )
   ```

   在 JavaScript 中加载这个模块会导致实例化错误。

2. **类型不匹配:** 如果初始化表达式的类型与全局变量的声明类型不匹配，WebAssembly 虚拟机也会报错。

   **例子 (概念性):**

   ```wat
   (module
     (global (mut i32) (f32.const 1.0)) ;; 尝试用浮点数初始化整数
     (export "my_global" (global 0))
   )
   ```

   尝试加载这个模块同样会导致实例化错误。

3. **对可变全局变量的引用 (在初始化表达式中):**  WebAssembly 的初始化表达式中通常不允许直接引用可变的全局变量。`GenerateInitExpr` 的代码试图避免这种情况，只使用不可变的全局变量。如果生成了引用可变全局变量的初始化表达式，则会导致验证错误。

**第 6 部分功能归纳:**

考虑到这是第 6 部分，并且代码专注于 `GenerateInitExpr`，我们可以推断出整个 `random-module-generation.cc` 文件的目的是**生成随机的、有效的 WebAssembly 模块以用于模糊测试**。

* **前面的部分 (1-5)** 可能涉及生成模块的更基础的结构，例如：
    * 定义类型 (函数签名、结构体、数组)。
    * 声明函数和导入。
    * 生成函数体内的指令序列。
    * 创建表和内存。

* **这一部分 (第 6 部分)** 专注于**生成用于初始化全局变量、表元素和数据段的表达式**。这是模块构建过程中的一个关键环节，确保这些元素在模块实例化时具有初始值。`GenerateInitExpr` 函数是本部分的核心。

* **最后一部分 (第 7 部分)** 很可能负责将所有生成的组件组合在一起，最终生成一个完整的 WebAssembly 模块的字节码。这可能包括处理导出、起始函数等模块级别的属性。

总而言之，`GenerateInitExpr` 在随机 WebAssembly 模块生成过程中扮演着**生成初始化表达式**的关键角色，确保模块的全局变量和表等元素能够被赋予有效的初始值。这是构建一个可执行的 WebAssembly 模块所必需的步骤。

Prompt: 
```
这是目录为v8/src/wasm/fuzzing/random-module-generation.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/fuzzing/random-module-generation.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共7部分，请归纳一下它的功能

"""
 i = 0; i < num_globals; ++i) {
              int index = (start_index + i) % num_globals;
              if (builder->GetGlobalType(index) == type &&
                  !builder->IsMutableGlobal(index)) {
                return WasmInitExpr::GlobalGet(index);
              }
            }
            // Fall back to constant if no matching global was found.
          }
          return WasmInitExpr(range.getPseudoRandom<int32_t>());
        default:
          WasmInitExpr::Operator op = choice == 3   ? WasmInitExpr::kI32Add
                                      : choice == 4 ? WasmInitExpr::kI32Sub
                                                    : WasmInitExpr::kI32Mul;
          return WasmInitExpr::Binop(
              zone, op,
              GenerateInitExpr(zone, range, builder, kWasmI32, structs, arrays,
                               recursion_depth + 1),
              GenerateInitExpr(zone, range, builder, kWasmI32, structs, arrays,
                               recursion_depth + 1));
      }
    }
    case kI64: {
      if (range.size() == 0 || recursion_depth >= kMaxRecursionDepth) {
        return WasmInitExpr(int64_t{0});
      }
      // 50% to generate a constant, 50% to generate a binary operator.
      uint8_t choice = range.get<uint8_t>() % 6;
      switch (choice) {
        case 0:
        case 1:
        case 2:
          return WasmInitExpr(range.get<int64_t>());
        default:
          WasmInitExpr::Operator op = choice == 3   ? WasmInitExpr::kI64Add
                                      : choice == 4 ? WasmInitExpr::kI64Sub
                                                    : WasmInitExpr::kI64Mul;
          return WasmInitExpr::Binop(
              zone, op,
              GenerateInitExpr(zone, range, builder, kWasmI64, structs, arrays,
                               recursion_depth + 1),
              GenerateInitExpr(zone, range, builder, kWasmI64, structs, arrays,
                               recursion_depth + 1));
      }
    }
    case kF16:
    case kF32:
      return WasmInitExpr(0.0f);
    case kF64:
      return WasmInitExpr(0.0);
    case kS128: {
      uint8_t s128_const[kSimd128Size] = {0};
      return WasmInitExpr(s128_const);
    }
    case kRefNull: {
      bool null_only = false;
      switch (type.heap_representation()) {
        case HeapType::kNone:
        case HeapType::kNoFunc:
        case HeapType::kNoExtern:
          null_only = true;
          break;
        default:
          break;
      }
      if (range.size() == 0 || recursion_depth >= kMaxRecursionDepth ||
          null_only || (range.get<uint8_t>() % 4 == 0)) {
        return WasmInitExpr::RefNullConst(type.heap_type().representation());
      }
      [[fallthrough]];
    }
    case kRef: {
      switch (type.heap_representation()) {
        case HeapType::kStruct: {
          ModuleTypeIndex index =
              structs[range.get<uint8_t>() % structs.size()];
          return GenerateStructNewInitExpr(zone, range, builder, index, structs,
                                           arrays, recursion_depth);
        }
        case HeapType::kAny: {
          // Do not use 0 as the determining value here, otherwise an exhausted
          // {range} will generate an infinite recursion with the {kExtern}
          // case.
          if (recursion_depth < kMaxRecursionDepth && range.size() > 0 &&
              range.get<uint8_t>() % 4 == 3) {
            return WasmInitExpr::AnyConvertExtern(
                zone,
                GenerateInitExpr(zone, range, builder,
                                 ValueType::RefMaybeNull(HeapType::kExtern,
                                                         type.nullability()),
                                 structs, arrays, recursion_depth + 1));
          }
          [[fallthrough]];
        }
        case HeapType::kEq: {
          uint8_t choice = range.get<uint8_t>() % 3;
          HeapType::Representation subtype = choice == 0   ? HeapType::kI31
                                             : choice == 1 ? HeapType::kArray
                                                           : HeapType::kStruct;

          return GenerateInitExpr(
              zone, range, builder,
              ValueType::RefMaybeNull(subtype, type.nullability()), structs,
              arrays, recursion_depth);
        }
        case HeapType::kFunc: {
          uint32_t index =
              range.get<uint32_t>() % (builder->NumDeclaredFunctions() +
                                       builder->NumImportedFunctions());
          return WasmInitExpr::RefFuncConst(index);
        }
        case HeapType::kExtern:
          return WasmInitExpr::ExternConvertAny(
              zone, GenerateInitExpr(zone, range, builder,
                                     ValueType::RefMaybeNull(
                                         HeapType::kAny, type.nullability()),
                                     structs, arrays, recursion_depth + 1));
        case HeapType::kI31:
          return WasmInitExpr::RefI31(
              zone, GenerateInitExpr(zone, range, builder, kWasmI32, structs,
                                     arrays, recursion_depth + 1));
        case HeapType::kArray: {
          ModuleTypeIndex index = arrays[range.get<uint8_t>() % arrays.size()];
          return GenerateArrayInitExpr(zone, range, builder, index, structs,
                                       arrays, recursion_depth);
        }
        case HeapType::kNone:
        case HeapType::kNoFunc:
        case HeapType::kNoExtern:
          UNREACHABLE();
        default: {
          ModuleTypeIndex index = type.ref_index();
          if (builder->IsStructType(index)) {
            return GenerateStructNewInitExpr(zone, range, builder, index,
                                             structs, arrays, recursion_depth);
          } else if (builder->IsArrayType(index)) {
            return GenerateArrayInitExpr(zone, range, builder, index, structs,
                                         arrays, recursion_depth);
          } else {
            DCHECK(builder->IsSignature(index));
            for (int i = 0; i < builder->NumDeclaredFunctions(); ++i) {
              if (builder->GetFunction(i)->sig_index() == index) {
                return WasmInitExpr::RefFuncConst(
                    builder->NumImportedFunctions() + i);
              }
            }
            // There has to be at least one function per signature, otherwise
            // the init expression is unable to generate a non-nullable
            // reference with the correct type.
            UNREACHABLE();
          }
          UNREACHABLE();
        }
      }
    }
    case kVoid:
    case kRtt:
    case kTop:
    case kBottom:
      UNREACHABLE();
  }
}

}  // namespace

template <WasmModuleGenerationOptions options>
base::Vector<uint8_t> GenerateRandomWasmModule(
    Zone* zone, base::Vector<const uint8_t> data) {
  WasmModuleBuilder builder(zone);

  // Split input data in two parts:
  // - One for the "module" (types, globals, ..)
  // - One for all the function bodies
  // This prevents using a too large portion on the module resulting in
  // uninteresting function bodies.
  DataRange module_range(data);
  DataRange functions_range = module_range.split();
  std::vector<ModuleTypeIndex> function_signatures;

  static_assert(kMaxFunctions >= 1, "need min. 1 function");
  uint8_t num_functions = 1 + (module_range.get<uint8_t>() % kMaxFunctions);

  // In case of WasmGC expressions:
  // Add struct and array types first so that we get a chance to generate
  // these types in function signatures.
  // Currently, `BodyGen` assumes this order for struct/array/signature
  // definitions.
  // Otherwise, for non-WasmGC we can't use structs/arrays.
  uint8_t num_structs = 0;
  uint8_t num_arrays = 0;
  std::vector<ModuleTypeIndex> array_types;
  std::vector<ModuleTypeIndex> struct_types;

  // In case of WasmGC expressions:
  // We always add two default array types with mutable i8 and i16 elements,
  // respectively.
  constexpr uint8_t kNumDefaultArrayTypesForWasmGC = 2;
  if constexpr (ShouldGenerateWasmGC(options)) {
    // We need at least one struct and one array in order to support
    // WasmInitExpr for abstract types.
    num_structs = 1 + module_range.get<uint8_t>() % kMaxStructs;
    num_arrays = kNumDefaultArrayTypesForWasmGC +
                 module_range.get<uint8_t>() % kMaxArrays;
  }

  uint8_t num_signatures = num_functions;
  ModuleGen<options> gen_module(zone, &builder, &module_range, num_functions,
                                num_structs, num_arrays, num_signatures);

  // Add random number of memories.
  // TODO(v8:14674): Add a mode without declaring any memory or memory
  // instructions.
  gen_module.GenerateRandomMemories();

  uint8_t current_type_index = 0;
  // In case of WasmGC expressions, we create recursive groups for the recursive
  // types.
  std::map<uint8_t, uint8_t> explicit_rec_groups;
  if constexpr (ShouldGenerateWasmGC(options)) {
    // Put the types into random recursive groups.
    explicit_rec_groups = gen_module.GenerateRandomRecursiveGroups(
        kNumDefaultArrayTypesForWasmGC);

    // Add default array types.
    static constexpr ModuleTypeIndex kArrayI8{0};
    static constexpr ModuleTypeIndex kArrayI16{1};
    {
      ArrayType* a8 = zone->New<ArrayType>(kWasmI8, 1);
      CHECK_EQ(kArrayI8, builder.AddArrayType(a8, true, kNoSuperType));
      array_types.push_back(kArrayI8);
      ArrayType* a16 = zone->New<ArrayType>(kWasmI16, 1);
      CHECK_EQ(kArrayI16, builder.AddArrayType(a16, true, kNoSuperType));
      array_types.push_back(kArrayI16);
    }
    static_assert(kNumDefaultArrayTypesForWasmGC == kArrayI16.index + 1);
    current_type_index = kNumDefaultArrayTypesForWasmGC;

    // Add randomly generated structs.
    gen_module.GenerateRandomStructs(explicit_rec_groups, struct_types,
                                     current_type_index,
                                     kNumDefaultArrayTypesForWasmGC);
    DCHECK_EQ(current_type_index, kNumDefaultArrayTypesForWasmGC + num_structs);

    // Add randomly generated arrays.
    gen_module.GenerateRandomArrays(explicit_rec_groups, array_types,
                                    current_type_index);
    DCHECK_EQ(current_type_index, num_structs + num_arrays);
  }

  // We keep the signature for the first (main) function constant.
  constexpr bool kIsFinal = true;
  auto kMainFnSig = FixedSizeSignature<ValueType>::Returns(kWasmI32).Params(
      kWasmI32, kWasmI32, kWasmI32);
  function_signatures.push_back(
      builder.ForceAddSignature(&kMainFnSig, kIsFinal));
  current_type_index++;

  // Add randomly generated signatures.
  gen_module.GenerateRandomFunctionSigs(
      explicit_rec_groups, function_signatures, current_type_index, kIsFinal);
  DCHECK_EQ(current_type_index, num_functions + num_structs + num_arrays);

  // Add exceptions.
  int num_exceptions = 1 + (module_range.get<uint8_t>() % kMaxExceptions);
  gen_module.GenerateRandomExceptions(num_exceptions);

  // In case of WasmGC expressions:
  // Add the "wasm:js-string" imports to the module. They may or may not be
  // used later, but they'll always be available.
  StringImports strings = ShouldGenerateWasmGC(options)
                              ? gen_module.AddImportedStringImports()
                              : StringImports();

  // Generate function declarations before tables. This will be needed once we
  // have typed-function tables.
  std::vector<WasmFunctionBuilder*> functions;
  for (uint8_t i = 0; i < num_functions; i++) {
    // If we are using wasm-gc, we cannot allow signature normalization
    // performed by adding a function by {FunctionSig}, because we emit
    // everything in one recursive group which blocks signature
    // canonicalization.
    // TODO(14034): Relax this when we implement proper recursive-group
    // support.
    functions.push_back(builder.AddFunction(function_signatures[i]));
  }

  // Generate tables before function bodies, so they are available for table
  // operations. Generate tables before the globals, so tables don't
  // accidentally use globals in their initializer expressions.
  // Always generate at least one table for call_indirect.
  gen_module.GenerateRandomTables(array_types, struct_types);

  // Add globals.
  auto [globals, mutable_globals] =
      gen_module.GenerateRandomGlobals(array_types, struct_types);

  // Add passive data segments.
  int num_data_segments = module_range.get<uint8_t>() % kMaxPassiveDataSegments;
  for (int i = 0; i < num_data_segments; i++) {
    GeneratePassiveDataSegment(&module_range, &builder);
  }

  // Generate function bodies.
  for (int i = 0; i < num_functions; ++i) {
    WasmFunctionBuilder* f = functions[i];
    // On the last function don't split the DataRange but just use the
    // existing DataRange.
    DataRange function_range = i != num_functions - 1
                                   ? functions_range.split()
                                   : std::move(functions_range);
    BodyGen<options> gen_body(f, function_signatures, globals, mutable_globals,
                              struct_types, array_types, strings,
                              &function_range);
    const FunctionSig* sig = f->signature();
    base::Vector<const ValueType> return_types(sig->returns().begin(),
                                               sig->return_count());
    gen_body.InitializeNonDefaultableLocals(&function_range);
    gen_body.Generate(return_types, &function_range);
    // TODO(v8:14639): Disable SIMD expressions if needed, so that a module is
    // always generated.
    if (ShouldGenerateSIMD(options) && !CheckHardwareSupportsSimd() &&
        gen_body.HasSimd()) {
      return {};
    }
    f->Emit(kExprEnd);
    if (i == 0) builder.AddExport(base::CStrVector("main"), f);
  }

  ZoneBuffer buffer{zone};
  builder.WriteTo(&buffer);
  return base::VectorOf(buffer);
}

// Used by the initializer expression fuzzer.
base::Vector<uint8_t> GenerateWasmModuleForInitExpressions(
    Zone* zone, base::Vector<const uint8_t> data, size_t* count) {
  // Don't limit expressions for the initializer expression fuzzer.
  constexpr WasmModuleGenerationOptions options =
      WasmModuleGenerationOptions::kGenerateAll;
  WasmModuleBuilder builder(zone);

  DataRange module_range(data);
  std::vector<ModuleTypeIndex> function_signatures;
  std::vector<ModuleTypeIndex> array_types;
  std::vector<ModuleTypeIndex> struct_types;

  int num_globals = 1 + module_range.get<uint8_t>() % (kMaxGlobals + 1);

  uint8_t num_functions = num_globals;
  *count = num_functions;

  // We need at least one struct and one array in order to support
  // WasmInitExpr for abstract types.
  uint8_t num_structs = 1 + module_range.get<uint8_t>() % kMaxStructs;
  uint8_t num_arrays = 1 + module_range.get<uint8_t>() % kMaxArrays;
  uint16_t num_types = num_functions + num_structs + num_arrays;

  uint8_t current_type_index = 0;

  // Add random-generated types.
  uint8_t last_struct_type = current_type_index + num_structs;
  for (; current_type_index < last_struct_type; current_type_index++) {
    ModuleTypeIndex supertype = kNoSuperType;
    uint8_t num_fields = module_range.get<uint8_t>() % (kMaxStructFields + 1);

    uint32_t existing_struct_types = current_type_index;
    if (existing_struct_types > 0 && module_range.get<bool>()) {
      supertype =
          ModuleTypeIndex{module_range.get<uint8_t>() % existing_struct_types};
      num_fields += builder.GetStructType(supertype)->field_count();
    }
    StructType::Builder struct_builder(zone, num_fields);

    // Add all fields from super type.
    uint32_t field_index = 0;
    if (supertype != kNoSuperType) {
      const StructType* parent = builder.GetStructType(supertype);
      for (; field_index < parent->field_count(); ++field_index) {
        struct_builder.AddField(parent->field(field_index),
                                parent->mutability(field_index));
      }
    }
    for (; field_index < num_fields; field_index++) {
      ValueType type = GetValueTypeHelper<options>(
          &module_range, current_type_index, current_type_index,
          kIncludeNumericTypes, kIncludePackedTypes, kExcludeSomeGenerics);

      bool mutability = module_range.get<bool>();
      struct_builder.AddField(type, mutability);
    }
    StructType* struct_fuz = struct_builder.Build();
    ModuleTypeIndex index = builder.AddStructType(struct_fuz, false, supertype);
    struct_types.push_back(index);
  }

  for (; current_type_index < num_structs + num_arrays; current_type_index++) {
    ValueType type = GetValueTypeHelper<options>(
        &module_range, current_type_index, current_type_index,
        kIncludeNumericTypes, kIncludePackedTypes, kExcludeSomeGenerics);
    ModuleTypeIndex supertype = kNoSuperType;
    if (current_type_index > last_struct_type && module_range.get<bool>()) {
      uint32_t existing_array_types = current_type_index - last_struct_type;
      supertype =
          ModuleTypeIndex{last_struct_type +
                          (module_range.get<uint8_t>() % existing_array_types)};
      type = builder.GetArrayType(supertype)->element_type();
    }
    ArrayType* array_fuz = zone->New<ArrayType>(type, true);
    ModuleTypeIndex index = builder.AddArrayType(array_fuz, false, supertype);
    array_types.push_back(index);
  }

  // Choose global types and create function signatures.
  constexpr bool kIsFinal = true;
  std::vector<ValueType> globals;
  for (; current_type_index < num_types; current_type_index++) {
    ValueType return_type = GetValueTypeHelper<options>(
        &module_range, num_types - num_globals, num_types - num_globals,
        kIncludeNumericTypes, kExcludePackedTypes, kIncludeAllGenerics,
        kExcludeS128);
    globals.push_back(return_type);
    // Create a new function signature for each global. These functions will be
    // used to compare against the initializer value of the global.
    FunctionSig::Builder sig_builder(zone, 1, 0);
    sig_builder.AddReturn(return_type);
    ModuleTypeIndex signature_index =
        builder.ForceAddSignature(sig_builder.Get(), kIsFinal);
    function_signatures.push_back(signature_index);
  }

  std::vector<WasmFunctionBuilder*> functions;
  for (uint8_t i = 0; i < num_functions; i++) {
    functions.push_back(builder.AddFunction(function_signatures[i]));
  }

  // Create globals.
  std::vector<uint8_t> mutable_globals;
  std::vector<WasmInitExpr> init_exprs;
  init_exprs.reserve(num_globals);
  mutable_globals.reserve(num_globals);
  CHECK_EQ(globals.size(), num_globals);
  uint64_t mutabilities = module_range.get<uint64_t>();
  for (int i = 0; i < num_globals; ++i) {
    ValueType type = globals[i];
    // 50% of globals are immutable.
    const bool mutability = mutabilities & 1;
    mutabilities >>= 1;
    WasmInitExpr init_expr = GenerateInitExpr(
        zone, module_range, &builder, type, struct_types, array_types, 0);
    init_exprs.push_back(init_expr);
    auto buffer = zone->AllocateVector<char>(8);
    size_t len = base::SNPrintF(buffer, "g%i", i);
    builder.AddExportedGlobal(type, mutability, init_expr,
                              {buffer.begin(), len});
    if (mutability) mutable_globals.push_back(static_cast<uint8_t>(i));
  }

  // Create functions containing the initializer of each global as its function
  // body.
  for (int i = 0; i < num_functions; ++i) {
    WasmFunctionBuilder* f = functions[i];
    f->EmitFromInitializerExpression(init_exprs[i]);
    auto buffer = zone->AllocateVector<char>(8);
    size_t len = base::SNPrintF(buffer, "f%i", i);
    builder.AddExport({buffer.begin(), len}, f);
  }

  ZoneBuffer buffer{zone};
  builder.WriteTo(&buffer);
  return base::VectorOf(buffer);
}

namespace {

bool HasSameReturns(const FunctionSig* a, const FunctionSig* b) {
  if (a->return_count() != b->return_count()) return false;
  for (size_t i = 0; i < a->return_count(); ++i) {
    if (a->GetReturn(i) != b->GetReturn(i)) return false;
  }
  return true;
}

template <WasmModuleGenerationOptions options>
void EmitDeoptAndReturnValues(BodyGen<options> gen_body, WasmFunctionBuilder* f,
                              const FunctionSig* target_sig,
                              ModuleTypeIndex target_sig_index,
                              uint32_t global_index, uint32_t table_index,
                              bool use_table64, DataRange* data) {
  base::Vector<const ValueType> return_types = f->signature()->returns();
  // Split the return types randomly and generate some values before the
  // deopting call and some afterwards. (This makes sure that we have deopts
  // where there are values on the wasm value stack which are not used by the
  // deopting call itself.)
  uint32_t returns_split = data->get<uint8_t>() % (return_types.size() + 1);
  if (returns_split) {
    gen_body.Generate(return_types.SubVector(0, returns_split), data);
  }
  gen_body.Generate(target_sig->parameters(), data);
  f->EmitWithU32V(kExprGlobalGet, global_index);
  if (use_table64) {
    f->Emit(kExprI64UConvertI32);
  }
  // Tail calls can only be emitted if the return types match.
  bool same_returns = HasSameReturns(target_sig, f->signature());
  size_t option_count = (same_returns + 1) * 2;
  switch (data->get<uint8_t>() % option_count) {
    case 0:
      // Emit call_ref.
      f->Emit(kExprTableGet);
      f->EmitU32V(table_index);
      f->EmitWithPrefix(kExprRefCast);
      f->EmitI32V(target_sig_index);
      f->EmitWithU32V(kExprCallRef, target_sig_index);
      break;
    case 1:
      // Emit call_indirect.
      f->EmitWithU32V(kExprCallIndirect, target_sig_index);
      f->EmitByte(table_index);
      break;
    case 2:
      // Emit return_call_ref.
      f->Emit(kExprTableGet);
      f->EmitU32V(table_index);
      f->EmitWithPrefix(kExprRefCast);
      f->EmitI32V(target_sig_index);
      f->EmitWithU32V(kExprReturnCallRef, target_sig_index);
      break;
    case 3:
      // Emit return_call_indirect.
      f->EmitWithU32V(kExprReturnCallIndirect, target_sig_index);
      f->EmitByte(table_index);
      break;
    default:
      UNREACHABLE();
  }
  gen_body.ConsumeAndGenerate(target_sig->returns(),
                              return_types.SubVectorFrom(returns_split), data);
}

template <WasmModuleGenerationOptions options>
void EmitCallAndReturnValues(BodyGen<options> gen_body, WasmFunctionBuilder* f,
                             WasmFunctionBuilder* callee, uint32_t table_index,
                             bool use_table64, DataRange* data) {
  const FunctionSig* callee_sig = callee->signature();
  uint32_t callee_index =
      callee->func_index() + gen_body.NumImportedFunctions();

  base::Vector<const ValueType> return_types = f->signature()->returns();
  // Split the return types randomly and generate some values before the
  // deopting call and some afterwards to create more interesting test cases.
  uint32_t returns_split = data->get<uint8_t>() % (return_types.size() + 1);
  if (returns_split) {
    gen_body.Generate(return_types.SubVector(0, returns_split), data);
  }
  gen_body.Generate(callee_sig->parameters(), data);
  // Tail calls can only be emitted if the return types match.
  bool same_returns = HasSameReturns(callee_sig, f->signature());
  size_t option_count = (same_returns + 1) * 3;
  switch (data->get<uint8_t>() % option_count) {
    case 0:
      f->EmitWithU32V(kExprCallFunction, callee_index);
      break;
    case 1:
      f->EmitWithU32V(kExprRefFunc, callee_index);
      f->EmitWithU32V(kExprCallRef, callee->sig_index());
      break;
    case 2:
      // Note that this assumes that the declared function index is the same as
      // the index of the function in the table.
      use_table64 ? f->EmitI64Const(callee->func_index())
                  : f->EmitI32Const(callee->func_index());
      f->EmitWithU32V(kExprCallIndirect, callee->sig_index());
      f->EmitByte(table_index);
      break;
    case 3:
      f->EmitWithU32V(kExprReturnCall, callee_index);
      break;
    case 4:
      f->EmitWithU32V(kExprRefFunc, callee_index);
      f->EmitWithU32V(kExprReturnCallRef, callee->sig_index());
      break;
    case 5:
      // Note that this assumes that the declared function index is the same as
      // the index of the function in the table.
      use_table64 ? f->EmitI64Const(callee->func_index())
                  : f->EmitI32Const(callee->func_index());
      f->EmitWithU32V(kExprReturnCallIndirect, callee->sig_index());
      f->EmitByte(table_index);
      break;
    default:
      UNREACHABLE();
  }
  gen_body.ConsumeAndGenerate(callee_sig->returns(),
                              return_types.SubVectorFrom(returns_split), data);
}
}  // anonymous namespace

base::Vector<uint8_t> GenerateWasmModuleForDeopt(
    Zone* zone, base::Vector<const uint8_t> data,
    std::vector<std::string>& callees, std::vector<std::string>& inlinees) {
  // Don't limit the features for the deopt fuzzer.
  constexpr WasmModuleGenerationOptions options =
      WasmModuleGenerationOptions::kGenerateAll;
  WasmModuleBuilder builder(zone);

  DataRange range(data);
  std::vector<ModuleTypeIndex> function_signatures;
  std::vector<ModuleTypeIndex> array_types;
  std::vector<ModuleTypeIndex> struct_types;

  const int kMaxCallTargets = 5;
  const int kMaxInlinees = 3;

  // We need at least 2 call targets to be able to trigger a deopt.
  const int num_call_targets = 2 + range.get<uint8_t>() % (kMaxCallTargets - 1);
  const int num_inlinees = range.get<uint8_t>() % (kMaxInlinees + 1);

  // 1 main function + x inlinees + x callees.
  uint8_t num_functions = 1 + num_inlinees + num_call_targets;
  // 1 signature for all the callees, 1 signature for the main function +
  // 1 signature per inlinee.
  uint8_t num_signatures = 2 + num_inlinees;

  uint8_t num_structs = 1 + range.get<uint8_t>() % kMaxStructs;
  // In case of WasmGC expressions:
  // We always add two default array types with mutable i8 and i16 elements,
  // respectively.
  constexpr uint8_t kNumDefaultArrayTypesForWasmGC = 2;
  uint8_t num_arrays =
      range.get<uint8_t>() % kMaxArrays + kNumDefaultArrayTypesForWasmGC;
  // Just ignoring user-defined signature types in the signatures.
  uint16_t num_types = num_structs + num_arrays;

  uint8_t current_type_index = kNumDefaultArrayTypesForWasmGC;

  // Add random-generated types.
  ModuleGen<options> gen_module(zone, &builder, &range, num_functions,
                                num_structs, num_arrays, num_signatures);

  gen_module.GenerateRandomMemories();
  std::map<uint8_t, uint8_t> explicit_rec_groups =
      gen_module.GenerateRandomRecursiveGroups(kNumDefaultArrayTypesForWasmGC);
  // Add default array types.
  static constexpr ModuleTypeIndex kArrayI8{0};
  static constexpr ModuleTypeIndex kArrayI16{1};
  {
    ArrayType* a8 = zone->New<ArrayType>(kWasmI8, true);
    CHECK_EQ(kArrayI8, builder.AddArrayType(a8, true, kNoSuperType));
    array_types.push_back(kArrayI8);
    ArrayType* a16 = zone->New<ArrayType>(kWasmI16, true);
    CHECK_EQ(kArrayI16, builder.AddArrayType(a16, true, kNoSuperType));
    array_types.push_back(kArrayI16);
  }
  static_assert(kNumDefaultArrayTypesForWasmGC == kArrayI16.index + 1);
  gen_module.GenerateRandomStructs(explicit_rec_groups, struct_types,
                                   current_type_index,
                                   kNumDefaultArrayTypesForWasmGC);
  DCHECK_EQ(current_type_index, kNumDefaultArrayTypesForWasmGC + num_structs);
  gen_module.GenerateRandomArrays(explicit_rec_groups, array_types,
                                  current_type_index);
  DCHECK_EQ(current_type_index, num_structs + num_arrays);

  // Create signature for call target.
  std::vector<ValueType> return_types =
      GenerateTypes<options>(&range, num_types);
  constexpr bool kIsFinal = true;
  const FunctionSig* target_sig = CreateSignature(
      builder.zone(), base::VectorOf(GenerateTypes<options>(&range, num_types)),
      base::VectorOf(return_types));
  ModuleTypeIndex target_sig_index =
      builder.ForceAddSignature(target_sig, kIsFinal);

  for (int i = 0; i < num_call_targets; ++i) {
    // Simplification: All call targets of a call_ref / call_indirect have the
    // same signature.
    function_signatures.push_back(target_sig_index);
  }

  // Create signatures for inlinees.
  // Use the same return types with a certain chance. This increases the chance
  // to emit return calls.
  uint8_t use_same_return = range.get<uint8_t>();
  for (int i = 0; i < num_inlinees; ++i) {
    if ((use_same_return & (1 << i)) == 0) {
      return_types = GenerateTypes<options>(&range, num_types);
    }
    const FunctionSig* inlinee_sig = CreateSignature(
        builder.zone(),
        base::VectorOf(GenerateTypes<options>(&range, num_types)),
        base::VectorOf(return_types));
    function_signatures.push_back(
        builder.ForceAddSignature(inlinee_sig, kIsFinal));
  }

  // Create signature for main function.
  const FunctionSig* main_sig = CreateSignature(
      builder.zone(), base::VectorOf({kWasmI32}), base::VectorOf({kWasmI32}));
  function_signatures.push_back(builder.ForceAddSignature(main_sig, kIsFinal));

  DCHECK_EQ(function_signatures.back().index,
            num_structs + num_arrays + num_signatures - 1);

  // This needs to be done after the signatures are added.
  int num_exceptions = 1 + range.get<uint8_t>() % kMaxExceptions;
  gen_module.GenerateRandomExceptions(num_exceptions);
  StringImports strings = gen_module.AddImportedStringImports();

  // Add functions to module.
  std::vector<WasmFunctionBuilder*> functions;
  DCHECK_EQ(num_functions, function_signatures.size());
  functions.reserve(num_functions);
  for (uint8_t i = 0; i < num_functions; i++) {
    functions.push_back(builder.AddFunction(function_signatures[i]));
  }

  uint32_t num_entries = num_call_targets + num_inlinees;
  bool use_table64 = range.get<bool>();
  AddressType address_type =
      use_table64 ? AddressType::kI64 : AddressType::kI32;
  uint32_t table_index =
      builder.AddTable(kWasmFuncRef, num_entries, num_entries, address_type);
  WasmModuleBuilder::WasmElemSegment segment(
      zone, kWasmFuncRef, table_index,
      use_table64 ? WasmInitExpr(int64_t{0}) : WasmInitExpr(0));
  for (uint32_t i = 0; i < num_entries; i++) {
    segment.entries.emplace_back(
        WasmModuleBuilder::WasmElemSegment::Entry::kRefFuncEntry,
        builder.NumImportedFunctions() + i);
  }
  builder.AddElementSegment(std::move(segment));

  gen_module.GenerateRandomTables(array_types, struct_types);

  // Create global for call target index.
  // Simplification: This global is used to specify the call target at the deopt
  // point instead of passing the call target around dynamically.
  uint32_t global_index =
      builder.AddExportedGlobal(kWasmI32, true, WasmInitExpr(0),
                                base::StaticCharVector("call_target_index"));

  // Create inlinee bodies.
  for (int i = 0; i < num_inlinees; ++i) {
    uint32_t declared_func_index = i + num_call_targets;
    WasmFunctionBuilder* f = functions[declared_func_index];
    DataRange function_range = range.split();
    BodyGen<options> gen_body(f, function_signatures, {}, {}, struct_types,
                              array_types, strings, &function_range);
    const FunctionSig* sig = f->signature();
    base::Vector<const ValueType> return_types(sig->returns().begin(),
                                               sig->return_count());
    gen_body.InitializeNonDefaultableLocals(&function_range);
    if (i == 0) {
      // For the inner-most inlinee, emit the deopt point (e.g. a call_ref).
      EmitDeoptAndReturnValues(gen_body, f, target_sig, target_sig_index,
                               global_index, table_index, use_table64,
                               &function_range);
    } else {
      // All other inlinees call the previous inlinee.
      uint32_t callee_declared_index = declared_func_index - 1;
      EmitCallAndReturnValues(gen_body, f, functions[callee_declared_index],
                              table_index, use_table64, &function_range);
    }
    // TODO(v8:14639): Disable SIMD expressions if needed, so that a module is
    // always generated.
    if (ShouldGenerateSIMD(options) && !CheckHardwareSupportsSimd() &&
        gen_body.HasSimd()) {
      return {};
    }
    f->Emit(kExprEnd);
    auto buffer = zone->AllocateVector<char>(32);
    size_t len = base::SNPrintF(buffer, "inlinee_%i", i);
    builder.AddExport({buffer.begin(), len}, f);
    inlinees.emplace_back(buffer.begin(), len);
  }

  // Create main function body.
  {
    uint32_t de
"""


```