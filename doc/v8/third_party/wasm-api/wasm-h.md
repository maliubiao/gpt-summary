Response:
Let's break down the thought process for analyzing this C header file for the WebAssembly C API.

1. **Identify the Core Purpose:** The first line, "// WebAssembly C API", immediately tells us the fundamental goal of this header file. It's about providing a C interface for interacting with WebAssembly.

2. **Check for Torque:** The prompt mentions `.tq` extension. A quick scan reveals `#ifndef __WASM_H`, `#define __WASM_H`, and no `.tq` anywhere. Therefore, this is *not* a Torque file. This is important to note early on.

3. **High-Level Functionality (Initial Pass):** Read through the major sections indicated by comments like "// Auxiliaries", "// Runtime Environment", "// Type Representations", "// Runtime Objects", and "// Convenience". This gives a bird's-eye view of the API's organization.

4. **Auxiliaries:**  Focus on the definitions. `byte_t`, `float32_t`, `float64_t` are basic type aliases. The `own` macro is interesting and needs further investigation. The `WASM_DECLARE_OWN` and `WASM_DECLARE_VEC` macros look like code generation mechanisms, likely for simplifying the definition of various WebAssembly types and their vector counterparts.

5. **Ownership (`own`):** The comments explain the purpose of `own`. This is crucial for understanding memory management in this API. It's a convention for indicating who is responsible for deleting allocated memory. This is a key concept and worth highlighting.

6. **Vectors:** The `WASM_DECLARE_VEC` macro is used to define vector types. Note how it handles both plain types and pointer types (`ptr_or_none`). The associated `_new`, `_copy`, and `_delete` functions are standard for managing dynamic arrays.

7. **Runtime Environment:**  This section introduces `config`, `engine`, and `store`. These seem like the fundamental building blocks for setting up and managing the WebAssembly runtime. Think of it as initializing the environment.

8. **Type Representations:** This is where the core WebAssembly types are defined: `valtype`, `functype`, `globaltype`, `tabletype`, `memorytype`, `externtype`, `importtype`, `exporttype`. Pay attention to the structs and enums associated with each. For example, `wasm_limits_t` for tables and memories, `wasm_mutability_t` for globals.

9. **Runtime Objects:** This section deals with *instances* of the types defined previously, plus runtime concepts like `val` (values), `ref` (references), `frame` (call stack frames), `trap` (runtime errors), `foreign` (host objects), `module`, `func`, `global`, `table`, `memory`, and `instance`. Notice the `_new`, `_get`, `_set`, `_call`, etc., functions, which represent actions on these runtime objects.

10. **Convenience:** These are helper functions to make common tasks easier, particularly constructing various types like `wasm_valtype_t` and `wasm_functype_t`. This simplifies common usage patterns.

11. **JavaScript Relationship (Hypothesize and Verify):**  Think about how WebAssembly is used in JavaScript. JavaScript can load and execute WebAssembly modules. The types and concepts in the C API should have counterparts in the JavaScript WebAssembly API. For instance, `wasm_module_t` corresponds to `WebAssembly.Module`, `wasm_instance_t` to `WebAssembly.Instance`, and so on. This is where the JavaScript examples will come from.

12. **Code Logic and Examples:** Choose a few representative functionalities. Creating a function, calling a function, and interacting with memory are good examples. For each, come up with a simple, concrete scenario with specific input and expected output (even if the output is a pointer or a side effect).

13. **Common Programming Errors:** Think about pitfalls when working with C APIs, especially those involving manual memory management (due to the `own` concept). Forgetting to delete objects, using deleted objects, and type mismatches are common culprits.

14. **Structure the Output:** Organize the findings logically, as requested by the prompt. Start with the main functionalities, then address the `.tq` question, the JavaScript relationship with examples, code logic scenarios, and finally common errors. Use clear headings and bullet points.

15. **Refine and Elaborate:** Review the generated output. Are the explanations clear and concise? Are the examples accurate and easy to understand?  Add details where necessary. For example, explain *why* forgetting to delete memory is a problem (memory leaks).

**(Self-Correction Example during the process):**

*Initial Thought:*  "The `own` macro just means the parameter is passed by value."

*Correction:* "Wait, the comments explicitly say it's about *ownership* and being responsible for deletion. It's more like a smart pointer concept in C++ but done manually. I need to adjust my explanation to reflect this crucial aspect of memory management."

By following this systematic approach, combining high-level understanding with detailed examination and cross-referencing with the prompt's requirements, you can effectively analyze and explain the functionality of this C header file.
根据提供的 V8 源代码 `v8/third_party/wasm-api/wasm.h`，我们可以列举出它的功能如下：

**核心功能：定义 WebAssembly C API**

该头文件定义了一套 C 语言接口，用于与 WebAssembly 虚拟机进行交互。这套 API 允许 C/C++ 代码加载、编译、实例化和执行 WebAssembly 模块，并与 WebAssembly 模块中的函数、全局变量、表格和内存进行交互。

**具体功能模块：**

1. **辅助功能 (Auxiliaries):**
   - 定义了基本的类型别名，如 `byte_t`, `float32_t`, `float64_t`。
   - 提供了 `assertions()` 函数用于进行类型大小的静态断言，确保平台兼容性。
   - 定义了 `own` 宏，用于标记拥有所有权的指针，类似于智能指针的概念，指示谁负责释放内存。
   - 提供了用于管理动态数组的宏 `WASM_DECLARE_VEC`，以及相关的创建、复制和删除函数。
   - 定义了字节向量 `wasm_byte_vec_t`，并提供了从字符串创建字节向量的便捷函数 `wasm_name_new_from_string`。

2. **运行时环境 (Runtime Environment):**
   - **配置 (Configuration):** 定义了 `wasm_config_t` 及其创建和删除函数，用于配置 WebAssembly 虚拟机的行为。
   - **引擎 (Engine):** 定义了 `wasm_engine_t` 及其创建函数，代表 WebAssembly 虚拟机的执行引擎。可以基于不同的配置创建不同的引擎。
   - **存储 (Store):** 定义了 `wasm_store_t` 及其创建函数，代表 WebAssembly 运行时数据的存储区域，例如模块实例、函数实例等。

3. **类型表示 (Type Representations):**
   - 定义了 WebAssembly 中各种类型的表示，包括：
     - **值类型 (Value Types):** `wasm_valtype_t`，表示 i32, i64, f32, f64, anyref, funcref 等值类型。
     - **函数类型 (Function Types):** `wasm_functype_t`，表示函数的参数和返回值类型。
     - **全局变量类型 (Global Types):** `wasm_globaltype_t`，表示全局变量的类型和可变性。
     - **表格类型 (Table Types):** `wasm_tabletype_t`，表示表格元素的类型和大小限制。
     - **内存类型 (Memory Types):** `wasm_memorytype_t`，表示线性内存的大小限制。
     - **外部类型 (Extern Types):** `wasm_externtype_t`，用于统一表示外部导入和导出的实体类型（函数、全局变量、表格、内存）。
     - **导入类型 (Import Types):** `wasm_importtype_t`，表示模块导入的实体信息（模块名、导入名、类型）。
     - **导出类型 (Export Types):** `wasm_exporttype_t`，表示模块导出的实体信息（导出名、类型）。

4. **运行时对象 (Runtime Objects):**
   - 定义了 WebAssembly 运行时的各种对象实例：
     - **值 (Values):** `wasm_val_t`，表示 WebAssembly 中的值，包含类型和具体的值。
     - **引用 (References):** `wasm_ref_t`，所有运行时对象的基类引用。
     - **帧 (Frames):** `wasm_frame_t`，表示函数调用栈中的一帧，用于错误追踪。
     - **陷阱 (Traps):** `wasm_trap_t`，表示运行时错误。
     - **外部对象 (Foreign Objects):** `wasm_foreign_t`，用于嵌入器自定义的对象。
     - **模块 (Modules):** `wasm_module_t`，表示已编译的 WebAssembly 模块。
     - **函数实例 (Function Instances):** `wasm_func_t`，表示 WebAssembly 函数的实例。
     - **全局变量实例 (Global Instances):** `wasm_global_t`，表示 WebAssembly 全局变量的实例。
     - **表格实例 (Table Instances):** `wasm_table_t`，表示 WebAssembly 表格的实例。
     - **内存实例 (Memory Instances):** `wasm_memory_t`，表示 WebAssembly 线性内存的实例。
     - **外部实例 (Externals):** `wasm_extern_t`，统一表示外部导入和导出的实体实例。
     - **模块实例 (Module Instances):** `wasm_instance_t`，表示 WebAssembly 模块的实例化结果。

5. **便捷功能 (Convenience):**
   - 提供了一系列内联函数，用于简化常用类型的创建，例如快速创建特定类型的 `wasm_valtype_t` 和 `wasm_functype_t`。
   - 提供了处理指针类型的 `wasm_val_init_ptr` 和 `wasm_val_ptr` 函数。

**关于 .tq 结尾：**

如果 `v8/third_party/wasm-api/wasm.h` 以 `.tq` 结尾，那么它的确是一个 V8 Torque 源代码文件。Torque 是 V8 使用的一种类型安全的 DSL (Domain Specific Language)，用于生成高效的 C++ 代码，通常用于实现 V8 的内置函数和运行时功能。

**与 JavaScript 的关系及示例：**

`wasm.h` 中定义的 C API 是 V8 引擎中用于支持 WebAssembly 功能的基础。JavaScript 通过 `WebAssembly` 全局对象与 WebAssembly 进行交互，而 V8 引擎内部会使用这套 C API 来实现 JavaScript 提供的 WebAssembly 功能。

以下 JavaScript 示例展示了如何使用 JavaScript WebAssembly API，它背后会涉及到 `wasm.h` 中定义的概念：

```javascript
// 定义 WebAssembly 模块的二进制数据 (假设已经存在)
const wasmBinary = new Uint8Array([
  0, 97, 115, 109, 1, 0, 0, 0, // WASM 模块头
  1, 6, 1, 96, 0, 1, 127,     // 定义一个函数类型：无参数，返回 i32
  3, 2, 1, 0,                 // 导入部分：导入一个名为 "env" 模块的 "add" 函数
  7, 7, 1, 3, 97, 100, 100, 0, // 导出部分：导出名为 "exported_func" 的函数
  10, 8, 1, 6, 0, 0, 32, 0, 16, 0, 11 // 代码部分：调用导入的 "add" 函数
]);

// 创建 WebAssembly 模块
WebAssembly.compile(wasmBinary)
  .then(module => {
    // 创建导入对象
    const importObject = {
      env: {
        add: (a, b) => a + b // JavaScript 函数作为导入
      }
    };

    // 实例化 WebAssembly 模块
    const instance = new WebAssembly.Instance(module, importObject);

    // 调用导出的函数
    const result = instance.exports.exported_func();
    console.log(result); // 输出 JavaScript 函数 "add" 的结果
  });
```

在这个 JavaScript 示例中：

- `WebAssembly.compile(wasmBinary)`  在 V8 内部会使用 `wasm_module_new` 等 `wasm.h` 中定义的函数来编译 WebAssembly 二进制数据，创建 `wasm_module_t` 对象。
- `new WebAssembly.Instance(module, importObject)` 在 V8 内部会使用 `wasm_instance_new`，`wasm_func_new_with_env` 等函数来创建模块实例，并处理导入。
- `instance.exports.exported_func()` 在 V8 内部会使用 `wasm_func_call` 等函数来调用 WebAssembly 导出的函数。

**代码逻辑推理与假设输入输出：**

假设我们要创建一个简单的 WebAssembly 函数，它接收两个 i32 类型的参数并返回它们的和。

**假设输入：**

- 一个 `wasm_store_t` 实例。
- 一个 `wasm_functype_t` 实例，表示接收两个 i32 参数并返回一个 i32 结果。
- 一个 C 函数指针 `my_add_callback`，其签名为 `own wasm_trap_t* my_add_callback(const wasm_val_t args[], wasm_val_t results[])`，实现了加法逻辑。

**C 代码片段 (模拟 `my_add_callback`)：**

```c
own wasm_trap_t* my_add_callback(const wasm_val_t args[], wasm_val_t results[]) {
  if (args[0].kind != WASM_I32 || args[1].kind != WASM_I32) {
    // 处理参数类型错误
    return NULL; // 实际应返回一个 wasm_trap_t
  }
  results[0].kind = WASM_I32;
  results[0].of.i32 = args[0].of.i32 + args[1].of.i32;
  return NULL;
}
```

**输出：**

- 一个 `wasm_func_t` 实例，代表创建的 WebAssembly 函数。

**对应的 `wasm.h` 函数调用序列：**

```c
// 假设已经有了 store 和 func_type
wasm_func_t* my_wasm_func = wasm_func_new(store, func_type, my_add_callback);
```

**用户常见的编程错误：**

1. **内存管理错误：**  由于 `wasm.h` API 使用了 `own` 宏来指示所有权，用户容易忘记调用相应的 `wasm_xxx_delete` 函数来释放内存，导致内存泄漏。

   ```c
   // 错误示例：忘记删除创建的向量
   wasm_valtype_vec_t params;
   wasm_valtype_vec_new_empty(&params);
   // ... 使用 params ...
   // 忘记调用 wasm_valtype_vec_delete(&params); 导致内存泄漏
   ```

2. **类型不匹配：** 在创建实例或调用函数时，提供的参数类型与期望的类型不匹配会导致错误。

   ```c
   // 错误示例：尝试将 f32 类型的值传递给期望 i32 类型的函数
   wasm_val_t arg;
   arg.kind = WASM_F32;
   arg.of.f32 = 3.14f;
   wasm_val_t results[1];
   // 假设 func_instance 期望 i32 参数
   wasm_trap_t* trap = wasm_func_call(func_instance, &arg, results);
   if (trap) {
       // 处理类型不匹配导致的错误
   }
   ```

3. **使用已删除的对象：**  在对象被删除后继续使用，会导致未定义的行为。

   ```c
   // 错误示例：删除模块后尝试访问其导出
   wasm_module_delete(my_module);
   wasm_exporttype_vec_t exports;
   wasm_module_exports(my_module, &exports); // 错误：my_module 已被删除
   ```

4. **不正确的向量操作：**  例如，尝试访问超出向量边界的元素，或者不正确地初始化向量。

   ```c
   // 错误示例：访问超出向量边界
   wasm_valtype_vec_t params;
   wasm_valtype_vec_new_empty(&params);
   wasm_valtype_t* first_param = params.data[0]; // 错误：params 是空向量
   ```

理解 `wasm.h` 中定义的 API 和所有权模型对于正确地在 C/C++ 中嵌入和使用 WebAssembly 非常重要。

Prompt: 
```
这是目录为v8/third_party/wasm-api/wasm.h的一个v8源代码， 请列举一下它的功能, 
如果v8/third_party/wasm-api/wasm.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// WebAssembly C API

#ifndef __WASM_H
#define __WASM_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>


#ifdef __cplusplus
extern "C" {
#endif

///////////////////////////////////////////////////////////////////////////////
// Auxiliaries

// Machine types

inline void assertions() {
  static_assert(sizeof(float) == sizeof(uint32_t), "incompatible float type");
  static_assert(sizeof(double) == sizeof(uint64_t), "incompatible double type");
  static_assert(sizeof(intptr_t) == sizeof(uint32_t) ||
                sizeof(intptr_t) == sizeof(uint64_t),
                "incompatible pointer type");
}

typedef char byte_t;
typedef float float32_t;
typedef double float64_t;


// Ownership

#define own

// The qualifier `own` is used to indicate ownership of data in this API.
// It is intended to be interpreted similar to a `const` qualifier:
//
// - `own wasm_xxx_t*` owns the pointed-to data
// - `own wasm_xxx_t` distributes to all fields of a struct or union `xxx`
// - `own wasm_xxx_vec_t` owns the vector as well as its elements(!)
// - an `own` function parameter passes ownership from caller to callee
// - an `own` function result passes ownership from callee to caller
// - an exception are `own` pointer parameters named `out`, which are copy-back
//   output parameters passing back ownership from callee to caller
//
// Own data is created by `wasm_xxx_new` functions and some others.
// It must be released with the corresponding `wasm_xxx_delete` function.
//
// Deleting a reference does not necessarily delete the underlying object,
// it merely indicates that this owner no longer uses it.
//
// For vectors, `const wasm_xxx_vec_t` is used informally to indicate that
// neither the vector nor its elements should be modified.
// TODO: introduce proper `wasm_xxx_const_vec_t`?


#define WASM_DECLARE_OWN(name) \
  typedef struct wasm_##name##_t wasm_##name##_t; \
  \
  void wasm_##name##_delete(own wasm_##name##_t*);


// Vectors

#define WASM_DECLARE_VEC(name, ptr_or_none) \
  typedef struct wasm_##name##_vec_t { \
    size_t size; \
    wasm_##name##_t ptr_or_none* data; \
  } wasm_##name##_vec_t; \
  \
  void wasm_##name##_vec_new_empty(own wasm_##name##_vec_t* out); \
  void wasm_##name##_vec_new_uninitialized( \
    own wasm_##name##_vec_t* out, size_t); \
  void wasm_##name##_vec_new( \
    own wasm_##name##_vec_t* out, \
    size_t, own wasm_##name##_t ptr_or_none const[]); \
  void wasm_##name##_vec_copy( \
    own wasm_##name##_vec_t* out, wasm_##name##_vec_t*); \
  void wasm_##name##_vec_delete(own wasm_##name##_vec_t*);


// Byte vectors

typedef byte_t wasm_byte_t;
WASM_DECLARE_VEC(byte, )

typedef wasm_byte_vec_t wasm_name_t;

#define wasm_name wasm_byte_vec
#define wasm_name_new wasm_byte_vec_new
#define wasm_name_new_empty wasm_byte_vec_new_empty
#define wasm_name_new_new_uninitialized wasm_byte_vec_new_uninitialized
#define wasm_name_copy wasm_byte_vec_copy
#define wasm_name_delete wasm_byte_vec_delete

static inline void wasm_name_new_from_string(
  own wasm_name_t* out, const char* s
) {
  wasm_name_new(out, strlen(s) + 1, s);
}


///////////////////////////////////////////////////////////////////////////////
// Runtime Environment

// Configuration

WASM_DECLARE_OWN(config)

own wasm_config_t* wasm_config_new();

// Embedders may provide custom functions for manipulating configs.


// Engine

WASM_DECLARE_OWN(engine)

own wasm_engine_t* wasm_engine_new();
own wasm_engine_t* wasm_engine_new_with_config(own wasm_config_t*);


// Store

WASM_DECLARE_OWN(store)

own wasm_store_t* wasm_store_new(wasm_engine_t*);


///////////////////////////////////////////////////////////////////////////////
// Type Representations

// Type attributes

typedef uint8_t wasm_mutability_t;
enum wasm_mutability_enum {
  WASM_CONST,
  WASM_VAR,
};

typedef struct wasm_limits_t {
  uint32_t min;
  uint32_t max;
} wasm_limits_t;

static const uint32_t wasm_limits_max_default = 0xffffffff;


// Generic

#define WASM_DECLARE_TYPE(name) \
  WASM_DECLARE_OWN(name) \
  WASM_DECLARE_VEC(name, *) \
  \
  own wasm_##name##_t* wasm_##name##_copy(wasm_##name##_t*);


// Value Types

WASM_DECLARE_TYPE(valtype)

typedef uint8_t wasm_valkind_t;
enum wasm_valkind_enum {
  WASM_I32,
  WASM_I64,
  WASM_F32,
  WASM_F64,
  WASM_ANYREF = 128,
  WASM_FUNCREF,
};

own wasm_valtype_t* wasm_valtype_new(wasm_valkind_t);

wasm_valkind_t wasm_valtype_kind(const wasm_valtype_t*);

static inline bool wasm_valkind_is_num(wasm_valkind_t k) {
  return k < WASM_ANYREF;
}
static inline bool wasm_valkind_is_ref(wasm_valkind_t k) {
  return k >= WASM_ANYREF;
}

static inline bool wasm_valtype_is_num(const wasm_valtype_t* t) {
  return wasm_valkind_is_num(wasm_valtype_kind(t));
}
static inline bool wasm_valtype_is_ref(const wasm_valtype_t* t) {
  return wasm_valkind_is_ref(wasm_valtype_kind(t));
}


// Function Types

WASM_DECLARE_TYPE(functype)

own wasm_functype_t* wasm_functype_new(
  own wasm_valtype_vec_t* params, own wasm_valtype_vec_t* results);

const wasm_valtype_vec_t* wasm_functype_params(const wasm_functype_t*);
const wasm_valtype_vec_t* wasm_functype_results(const wasm_functype_t*);


// Global Types

WASM_DECLARE_TYPE(globaltype)

own wasm_globaltype_t* wasm_globaltype_new(
  own wasm_valtype_t*, wasm_mutability_t);

const wasm_valtype_t* wasm_globaltype_content(const wasm_globaltype_t*);
wasm_mutability_t wasm_globaltype_mutability(const wasm_globaltype_t*);


// Table Types

WASM_DECLARE_TYPE(tabletype)

own wasm_tabletype_t* wasm_tabletype_new(
  own wasm_valtype_t*, const wasm_limits_t*);

const wasm_valtype_t* wasm_tabletype_element(const wasm_tabletype_t*);
const wasm_limits_t* wasm_tabletype_limits(const wasm_tabletype_t*);


// Memory Types

WASM_DECLARE_TYPE(memorytype)

own wasm_memorytype_t* wasm_memorytype_new(const wasm_limits_t*);

const wasm_limits_t* wasm_memorytype_limits(const wasm_memorytype_t*);


// Extern Types

WASM_DECLARE_TYPE(externtype)

typedef uint8_t wasm_externkind_t;
enum wasm_externkind_enum {
  WASM_EXTERN_FUNC,
  WASM_EXTERN_GLOBAL,
  WASM_EXTERN_TABLE,
  WASM_EXTERN_MEMORY,
};

wasm_externkind_t wasm_externtype_kind(const wasm_externtype_t*);

wasm_externtype_t* wasm_functype_as_externtype(wasm_functype_t*);
wasm_externtype_t* wasm_globaltype_as_externtype(wasm_globaltype_t*);
wasm_externtype_t* wasm_tabletype_as_externtype(wasm_tabletype_t*);
wasm_externtype_t* wasm_memorytype_as_externtype(wasm_memorytype_t*);

wasm_functype_t* wasm_externtype_as_functype(wasm_externtype_t*);
wasm_globaltype_t* wasm_externtype_as_globaltype(wasm_externtype_t*);
wasm_tabletype_t* wasm_externtype_as_tabletype(wasm_externtype_t*);
wasm_memorytype_t* wasm_externtype_as_memorytype(wasm_externtype_t*);

const wasm_externtype_t* wasm_functype_as_externtype_const(const wasm_functype_t*);
const wasm_externtype_t* wasm_globaltype_as_externtype_const(const wasm_globaltype_t*);
const wasm_externtype_t* wasm_tabletype_as_externtype_const(const wasm_tabletype_t*);
const wasm_externtype_t* wasm_memorytype_as_externtype_const(const wasm_memorytype_t*);

const wasm_functype_t* wasm_externtype_as_functype_const(const wasm_externtype_t*);
const wasm_globaltype_t* wasm_externtype_as_globaltype_const(const wasm_externtype_t*);
const wasm_tabletype_t* wasm_externtype_as_tabletype_const(const wasm_externtype_t*);
const wasm_memorytype_t* wasm_externtype_as_memorytype_const(const wasm_externtype_t*);


// Import Types

WASM_DECLARE_TYPE(importtype)

own wasm_importtype_t* wasm_importtype_new(
  own wasm_name_t* module, own wasm_name_t* name, own wasm_externtype_t*);

const wasm_name_t* wasm_importtype_module(const wasm_importtype_t*);
const wasm_name_t* wasm_importtype_name(const wasm_importtype_t*);
const wasm_externtype_t* wasm_importtype_type(const wasm_importtype_t*);


// Export Types

WASM_DECLARE_TYPE(exporttype)

own wasm_exporttype_t* wasm_exporttype_new(
  own wasm_name_t*, own wasm_externtype_t*);

const wasm_name_t* wasm_exporttype_name(const wasm_exporttype_t*);
const wasm_externtype_t* wasm_exporttype_type(const wasm_exporttype_t*);


///////////////////////////////////////////////////////////////////////////////
// Runtime Objects

// Values

struct wasm_ref_t;

typedef struct wasm_val_t {
  wasm_valkind_t kind;
  union {
    int32_t i32;
    int64_t i64;
    float32_t f32;
    float64_t f64;
    struct wasm_ref_t* ref;
  } of;
} wasm_val_t;

void wasm_val_delete(own wasm_val_t* v);
void wasm_val_copy(own wasm_val_t* out, const wasm_val_t*);

WASM_DECLARE_VEC(val, )


// References

#define WASM_DECLARE_REF_BASE(name)                                        \
  WASM_DECLARE_OWN(name)                                                   \
                                                                           \
  own wasm_##name##_t* wasm_##name##_copy(const wasm_##name##_t*);         \
  bool wasm_##name##_same(const wasm_##name##_t*, const wasm_##name##_t*); \
                                                                           \
  void* wasm_##name##_get_host_info(const wasm_##name##_t*);               \
  void wasm_##name##_set_host_info(wasm_##name##_t*, void*);               \
  void wasm_##name##_set_host_info_with_finalizer(wasm_##name##_t*, void*, \
                                                  void (*)(void*));

#define WASM_DECLARE_REF(name) \
  WASM_DECLARE_REF_BASE(name) \
  \
  wasm_ref_t* wasm_##name##_as_ref(wasm_##name##_t*); \
  wasm_##name##_t* wasm_ref_as_##name(wasm_ref_t*); \
  const wasm_ref_t* wasm_##name##_as_ref_const(const wasm_##name##_t*); \
  const wasm_##name##_t* wasm_ref_as_##name##_const(const wasm_ref_t*);

#define WASM_DECLARE_SHARABLE_REF(name) \
  WASM_DECLARE_REF(name) \
  WASM_DECLARE_OWN(shared_##name) \
  \
  own wasm_shared_##name##_t* wasm_##name##_share(const wasm_##name##_t*); \
  own wasm_##name##_t* wasm_##name##_obtain(wasm_store_t*, const wasm_shared_##name##_t*);


WASM_DECLARE_REF_BASE(ref)


// Frames

WASM_DECLARE_OWN(frame)
WASM_DECLARE_VEC(frame, *)
own wasm_frame_t* wasm_frame_copy(const wasm_frame_t*);

struct wasm_instance_t* wasm_frame_instance(const wasm_frame_t*);
uint32_t wasm_frame_func_index(const wasm_frame_t*);
size_t wasm_frame_func_offset(const wasm_frame_t*);
size_t wasm_frame_module_offset(const wasm_frame_t*);


// Traps

typedef wasm_name_t wasm_message_t;  // null terminated

WASM_DECLARE_REF(trap)

own wasm_trap_t* wasm_trap_new(wasm_store_t* store, const wasm_message_t*);

void wasm_trap_message(const wasm_trap_t*, own wasm_message_t* out);
own wasm_frame_t* wasm_trap_origin(const wasm_trap_t*);
void wasm_trap_trace(const wasm_trap_t*, own wasm_frame_vec_t* out);


// Foreign Objects

WASM_DECLARE_REF(foreign)

own wasm_foreign_t* wasm_foreign_new(wasm_store_t*);


// Modules

WASM_DECLARE_SHARABLE_REF(module)

own wasm_module_t* wasm_module_new(
  wasm_store_t*, const wasm_byte_vec_t* binary);

bool wasm_module_validate(wasm_store_t*, const wasm_byte_vec_t* binary);

void wasm_module_imports(const wasm_module_t*, own wasm_importtype_vec_t* out);
void wasm_module_exports(const wasm_module_t*, own wasm_exporttype_vec_t* out);

void wasm_module_serialize(const wasm_module_t*, own wasm_byte_vec_t* out);
own wasm_module_t* wasm_module_deserialize(wasm_store_t*, const wasm_byte_vec_t*);


// Function Instances

WASM_DECLARE_REF(func)

typedef own wasm_trap_t* (*wasm_func_callback_t)(
  const wasm_val_t args[], wasm_val_t results[]);
typedef own wasm_trap_t* (*wasm_func_callback_with_env_t)(
  void* env, const wasm_val_t args[], wasm_val_t results[]);

own wasm_func_t* wasm_func_new(
  wasm_store_t*, const wasm_functype_t*, wasm_func_callback_t);
own wasm_func_t* wasm_func_new_with_env(
  wasm_store_t*, const wasm_functype_t* type, wasm_func_callback_with_env_t,
  void* env, void (*finalizer)(void*));

own wasm_functype_t* wasm_func_type(const wasm_func_t*);
size_t wasm_func_param_arity(const wasm_func_t*);
size_t wasm_func_result_arity(const wasm_func_t*);

own wasm_trap_t* wasm_func_call(
  const wasm_func_t*, const wasm_val_t args[], wasm_val_t results[]);


// Global Instances

WASM_DECLARE_REF(global)

own wasm_global_t* wasm_global_new(
  wasm_store_t*, const wasm_globaltype_t*, const wasm_val_t*);

own wasm_globaltype_t* wasm_global_type(const wasm_global_t*);

void wasm_global_get(const wasm_global_t*, own wasm_val_t* out);
void wasm_global_set(wasm_global_t*, const wasm_val_t*);


// Table Instances

WASM_DECLARE_REF(table)

typedef uint32_t wasm_table_size_t;

own wasm_table_t* wasm_table_new(
  wasm_store_t*, const wasm_tabletype_t*, wasm_ref_t* init);

own wasm_tabletype_t* wasm_table_type(const wasm_table_t*);

own wasm_ref_t* wasm_table_get(const wasm_table_t*, wasm_table_size_t index);
bool wasm_table_set(wasm_table_t*, wasm_table_size_t index, wasm_ref_t*);

wasm_table_size_t wasm_table_size(const wasm_table_t*);
bool wasm_table_grow(wasm_table_t*, wasm_table_size_t delta, wasm_ref_t* init);


// Memory Instances

WASM_DECLARE_REF(memory)

typedef uint32_t wasm_memory_pages_t;

static const size_t MEMORY_PAGE_SIZE = 0x10000;

own wasm_memory_t* wasm_memory_new(wasm_store_t*, const wasm_memorytype_t*);

own wasm_memorytype_t* wasm_memory_type(const wasm_memory_t*);

byte_t* wasm_memory_data(wasm_memory_t*);
size_t wasm_memory_data_size(const wasm_memory_t*);

wasm_memory_pages_t wasm_memory_size(const wasm_memory_t*);
bool wasm_memory_grow(wasm_memory_t*, wasm_memory_pages_t delta);


// Externals

WASM_DECLARE_REF(extern)
WASM_DECLARE_VEC(extern, *)

wasm_externkind_t wasm_extern_kind(const wasm_extern_t*);
own wasm_externtype_t* wasm_extern_type(const wasm_extern_t*);

wasm_extern_t* wasm_func_as_extern(wasm_func_t*);
wasm_extern_t* wasm_global_as_extern(wasm_global_t*);
wasm_extern_t* wasm_table_as_extern(wasm_table_t*);
wasm_extern_t* wasm_memory_as_extern(wasm_memory_t*);

wasm_func_t* wasm_extern_as_func(wasm_extern_t*);
wasm_global_t* wasm_extern_as_global(wasm_extern_t*);
wasm_table_t* wasm_extern_as_table(wasm_extern_t*);
wasm_memory_t* wasm_extern_as_memory(wasm_extern_t*);

const wasm_extern_t* wasm_func_as_extern_const(const wasm_func_t*);
const wasm_extern_t* wasm_global_as_extern_const(const wasm_global_t*);
const wasm_extern_t* wasm_table_as_extern_const(const wasm_table_t*);
const wasm_extern_t* wasm_memory_as_extern_const(const wasm_memory_t*);

const wasm_func_t* wasm_extern_as_func_const(const wasm_extern_t*);
const wasm_global_t* wasm_extern_as_global_const(const wasm_extern_t*);
const wasm_table_t* wasm_extern_as_table_const(const wasm_extern_t*);
const wasm_memory_t* wasm_extern_as_memory_const(const wasm_extern_t*);


// Module Instances

WASM_DECLARE_REF(instance)

own wasm_instance_t* wasm_instance_new(
  wasm_store_t*, const wasm_module_t*, const wasm_extern_t* const imports[],
  own wasm_trap_t**
);

void wasm_instance_exports(const wasm_instance_t*, own wasm_extern_vec_t* out);


///////////////////////////////////////////////////////////////////////////////
// Convenience

// Value Type construction short-hands

static inline own wasm_valtype_t* wasm_valtype_new_i32() {
  return wasm_valtype_new(WASM_I32);
}
static inline own wasm_valtype_t* wasm_valtype_new_i64() {
  return wasm_valtype_new(WASM_I64);
}
static inline own wasm_valtype_t* wasm_valtype_new_f32() {
  return wasm_valtype_new(WASM_F32);
}
static inline own wasm_valtype_t* wasm_valtype_new_f64() {
  return wasm_valtype_new(WASM_F64);
}

static inline own wasm_valtype_t* wasm_valtype_new_anyref() {
  return wasm_valtype_new(WASM_ANYREF);
}
static inline own wasm_valtype_t* wasm_valtype_new_funcref() {
  return wasm_valtype_new(WASM_FUNCREF);
}


// Function Types construction short-hands

static inline own wasm_functype_t* wasm_functype_new_0_0() {
  wasm_valtype_vec_t params, results;
  wasm_valtype_vec_new_empty(&params);
  wasm_valtype_vec_new_empty(&results);
  return wasm_functype_new(&params, &results);
}

static inline own wasm_functype_t* wasm_functype_new_1_0(
  own wasm_valtype_t* p
) {
  wasm_valtype_t* ps[1] = {p};
  wasm_valtype_vec_t params, results;
  wasm_valtype_vec_new(&params, 1, ps);
  wasm_valtype_vec_new_empty(&results);
  return wasm_functype_new(&params, &results);
}

static inline own wasm_functype_t* wasm_functype_new_2_0(
  own wasm_valtype_t* p1, own wasm_valtype_t* p2
) {
  wasm_valtype_t* ps[2] = {p1, p2};
  wasm_valtype_vec_t params, results;
  wasm_valtype_vec_new(&params, 2, ps);
  wasm_valtype_vec_new_empty(&results);
  return wasm_functype_new(&params, &results);
}

static inline own wasm_functype_t* wasm_functype_new_3_0(
  own wasm_valtype_t* p1, own wasm_valtype_t* p2, own wasm_valtype_t* p3
) {
  wasm_valtype_t* ps[3] = {p1, p2, p3};
  wasm_valtype_vec_t params, results;
  wasm_valtype_vec_new(&params, 3, ps);
  wasm_valtype_vec_new_empty(&results);
  return wasm_functype_new(&params, &results);
}

static inline own wasm_functype_t* wasm_functype_new_0_1(
  own wasm_valtype_t* r
) {
  wasm_valtype_t* rs[1] = {r};
  wasm_valtype_vec_t params, results;
  wasm_valtype_vec_new_empty(&params);
  wasm_valtype_vec_new(&results, 1, rs);
  return wasm_functype_new(&params, &results);
}

static inline own wasm_functype_t* wasm_functype_new_1_1(
  own wasm_valtype_t* p, own wasm_valtype_t* r
) {
  wasm_valtype_t* ps[1] = {p};
  wasm_valtype_t* rs[1] = {r};
  wasm_valtype_vec_t params, results;
  wasm_valtype_vec_new(&params, 1, ps);
  wasm_valtype_vec_new(&results, 1, rs);
  return wasm_functype_new(&params, &results);
}

static inline own wasm_functype_t* wasm_functype_new_2_1(
  own wasm_valtype_t* p1, own wasm_valtype_t* p2, own wasm_valtype_t* r
) {
  wasm_valtype_t* ps[2] = {p1, p2};
  wasm_valtype_t* rs[1] = {r};
  wasm_valtype_vec_t params, results;
  wasm_valtype_vec_new(&params, 2, ps);
  wasm_valtype_vec_new(&results, 1, rs);
  return wasm_functype_new(&params, &results);
}

static inline own wasm_functype_t* wasm_functype_new_3_1(
  own wasm_valtype_t* p1, own wasm_valtype_t* p2, own wasm_valtype_t* p3,
  own wasm_valtype_t* r
) {
  wasm_valtype_t* ps[3] = {p1, p2, p3};
  wasm_valtype_t* rs[1] = {r};
  wasm_valtype_vec_t params, results;
  wasm_valtype_vec_new(&params, 3, ps);
  wasm_valtype_vec_new(&results, 1, rs);
  return wasm_functype_new(&params, &results);
}

static inline own wasm_functype_t* wasm_functype_new_0_2(
  own wasm_valtype_t* r1, own wasm_valtype_t* r2
) {
  wasm_valtype_t* rs[2] = {r1, r2};
  wasm_valtype_vec_t params, results;
  wasm_valtype_vec_new_empty(&params);
  wasm_valtype_vec_new(&results, 2, rs);
  return wasm_functype_new(&params, &results);
}

static inline own wasm_functype_t* wasm_functype_new_1_2(
  own wasm_valtype_t* p, own wasm_valtype_t* r1, own wasm_valtype_t* r2
) {
  wasm_valtype_t* ps[1] = {p};
  wasm_valtype_t* rs[2] = {r1, r2};
  wasm_valtype_vec_t params, results;
  wasm_valtype_vec_new(&params, 1, ps);
  wasm_valtype_vec_new(&results, 2, rs);
  return wasm_functype_new(&params, &results);
}

static inline own wasm_functype_t* wasm_functype_new_2_2(
  own wasm_valtype_t* p1, own wasm_valtype_t* p2,
  own wasm_valtype_t* r1, own wasm_valtype_t* r2
) {
  wasm_valtype_t* ps[2] = {p1, p2};
  wasm_valtype_t* rs[2] = {r1, r2};
  wasm_valtype_vec_t params, results;
  wasm_valtype_vec_new(&params, 2, ps);
  wasm_valtype_vec_new(&results, 2, rs);
  return wasm_functype_new(&params, &results);
}

static inline own wasm_functype_t* wasm_functype_new_3_2(
  own wasm_valtype_t* p1, own wasm_valtype_t* p2, own wasm_valtype_t* p3,
  own wasm_valtype_t* r1, own wasm_valtype_t* r2
) {
  wasm_valtype_t* ps[3] = {p1, p2, p3};
  wasm_valtype_t* rs[2] = {r1, r2};
  wasm_valtype_vec_t params, results;
  wasm_valtype_vec_new(&params, 3, ps);
  wasm_valtype_vec_new(&results, 2, rs);
  return wasm_functype_new(&params, &results);
}


// Value construction short-hands

static inline void wasm_val_init_ptr(own wasm_val_t* out, void* p) {
#if UINTPTR_MAX == UINT32_MAX
  out->kind = WASM_I32;
  out->of.i32 = (intptr_t)p;
#elif UINTPTR_MAX == UINT64_MAX
  out->kind = WASM_I64;
  out->of.i64 = (intptr_t)p;
#endif
}

static inline void* wasm_val_ptr(const wasm_val_t* val) {
#if UINTPTR_MAX == UINT32_MAX
  return (void*)(intptr_t)val->of.i32;
#elif UINTPTR_MAX == UINT64_MAX
  return (void*)(intptr_t)val->of.i64;
#endif
}


///////////////////////////////////////////////////////////////////////////////

#undef own

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // #ifdef __WASM_H

"""

```