Response:
Let's break down the thought process for analyzing this C++ header file and fulfilling the request.

1. **Understand the Core Request:** The request asks for the *functionality* of the provided C++ header file (`v8/src/base/macros.h`). It also has specific sub-questions regarding `.tq` files, JavaScript relevance, logic examples, and common errors.

2. **Initial Scan and Categorization:**  The `#define` directives immediately stand out. These are preprocessor macros. The `#include` directives indicate dependencies on other headers. A quick scan reveals macros related to:
    * Concatenation and unique identifiers (`CONCAT`, `UNIQUE_IDENTIFIER`)
    * Argument counting and access (`COUNT_MACRO_ARGS`, `GET_NTH_ARG`)
    * Parenthesis removal (`UNPAREN`)
    * Size calculations (`arraysize`)
    * Bit manipulation (`bit_cast`)
    * Disabling/managing class features (copying, construction, allocation) (`DISALLOW_ASSIGN`, `DISALLOW_IMPLICIT_CONSTRUCTORS`, `MOVE_ONLY_*`, `DISALLOW_NEW_AND_DELETE`)
    * Compiler/sanitizer flags (`V8_USE_*_SANITIZER`, `DISABLE_CFI_*`)
    * Function name retrieval (`V8_PRETTY_FUNCTION_VALUE_OR`)
    * Type traits (`is_trivially_copyable`, `ASSERT_TRIVIALLY_COPYABLE`, `ASSERT_NOT_TRIVIALLY_COPYABLE`)
    * Suppressing warnings (`USE`)
    * Casting (`implicit_cast`)
    * Constant definitions (`V8PRIxPTR`, etc.)
    * Rounding functions (`RoundDown`, `RoundUp`)
    * Alignment checks (`IsAligned`, `AlignedAddress`, `RoundUpAddress`)
    * Bounds checking (`is_inbounds`)
    * Export directives for shared libraries (`V8_EXPORT_*`)
    * Conditional compilation based on features (`IF_WASM`, `IF_TSAN`, etc.)
    * Google Test compatibility (`FRIEND_TEST`)

3. **Address the `.tq` question:** The request specifically asks about the `.tq` extension. Based on general V8 knowledge, `.tq` files are associated with Torque. So, the answer is to confirm this.

4. **Identify JavaScript Relevance:**  The key is to recognize that while this is C++ code, V8 *implements* JavaScript. Therefore, macros that manage memory, handle types, or control execution flow could indirectly relate to JavaScript's behavior. Specifically:
    * **`arraysize`:**  Relates to how arrays are handled internally, which has a JavaScript equivalent.
    * **`bit_cast`:** Although low-level, this can be used in the implementation of JavaScript's type conversions.
    * **`DISALLOW_*` macros:** These influence how V8's internal objects are managed, impacting performance and preventing unintended behavior, which ultimately affects the JavaScript engine.
    * **Sanitizer flags:** These are used for debugging and ensuring the correctness of the engine, indirectly ensuring the stability of JavaScript execution.

5. **Develop JavaScript Examples:**  For the relevant macros, create simple JavaScript snippets that demonstrate the *concept* the C++ macro is handling, even if there isn't a direct 1:1 mapping. For example, `arraysize` relates to JavaScript array lengths, `bit_cast` loosely relates to type conversions, and the `DISALLOW_*` macros relate to the *impossibility* of certain actions in JavaScript (like directly accessing memory management).

6. **Create Logic Examples (Input/Output):** For macros that perform transformations or calculations (like `CONCAT`, `UNIQUE_IDENTIFIER`, `COUNT_MACRO_ARGS`, `GET_NTH_ARG`, `RoundUp`, `RoundDown`), provide concrete examples with hypothetical inputs and their expected outputs. This demonstrates how the macros work.

7. **Consider Common Programming Errors:** Think about how these macros might prevent or highlight common C++ mistakes. For example:
    * Using `arraysize` on a pointer.
    * Accidentally copying objects that should not be copied (addressed by `DISALLOW_COPY`).
    * Forgetting to handle edge cases in rounding.
    * Incorrect assumptions about type sizes when using `bit_cast`.

8. **Structure the Output:** Organize the information logically. Start with a general overview of the header file's purpose. Then, address each part of the request systematically:
    * List the functionalities with explanations.
    * Answer the `.tq` question.
    * Explain the JavaScript relevance with examples.
    * Provide logic examples with input/output.
    * Discuss common programming errors.

9. **Refine and Elaborate:**  Review the generated information for clarity and accuracy. Add more detail where necessary. For instance, when explaining `bit_cast`, emphasize the safety concerns and when it should/shouldn't be used. For the JavaScript examples, explain *why* the C++ macro is relevant to the JavaScript concept.

10. **Self-Correction/Improvements during the Process:**
    * **Initial thought:** "Maybe I should try to find direct equivalents in JavaScript for every macro."  **Correction:**  Realize that direct equivalents might not exist, and focusing on the *underlying concept* is more useful.
    * **Initial thought:**  "Just list all the macros and their definitions." **Correction:** The request asks for *functionality*, so explain *what they do* and *why they are there*, not just their syntax.
    * **Realization:** Some macros are very technical (like the sanitizer flags). Explain their high-level purpose rather than getting bogged down in compiler details.

By following these steps, the goal is to provide a comprehensive and helpful analysis of the `macros.h` file that addresses all aspects of the original request. The process involves understanding the C++ preprocessor, the role of macros in a large project like V8, and the connection between the underlying C++ implementation and the JavaScript language it supports.
这是目录为 `v8/src/base/macros.h` 的一个 V8 源代码文件，它主要定义了一系列 C++ 预处理器宏，用于简化代码、提高可读性、进行编译时检查以及实现一些通用的编程模式。

以下是它的功能分类列举：

**1. 基本宏定义和辅助功能:**

*   **`EXPAND(X)`:**  这是一个无操作宏，用于绕过 MSVC 编译器在处理可变参数宏 (`VA_ARGS`) 时可能出现的问题。它可以强制展开宏。
*   **`NOTHING(...)`:**  另一个无操作宏，可以接受任意数量的参数，但什么也不做。用于某些需要提供参数但实际上不需要执行任何操作的场景。
*   **`CONCAT_(a, ...)` 和 `CONCAT(a, ...)`:** 用于将两个或多个标识符连接成一个新的标识符。`CONCAT_` 是内部实现，`CONCAT` 调用 `CONCAT_` 并带上 `__VA_ARGS__`，用于处理可变参数。
*   **`UNIQUE_IDENTIFIER(base)`:**  使用 `CONCAT` 和预定义的 `__COUNTER__` 宏生成唯一的标识符。这对于在局部作用域内避免命名冲突非常有用。

**2. 可变参数宏的工具:**

*   **`COUNT_MACRO_ARGS(...)`:**  计算传递给宏的参数数量。当前支持最多 8 个参数。它通过一系列的宏定义技巧实现。
*   **`GET_NTH_ARG(N, ...)`:**  获取传递给宏的参数列表中的第 N 个参数（从 0 开始索引）。当前支持最多获取第 7 个参数（N=7）。

**3. 括号处理宏:**

*   **`UNPAREN(X)`:**  移除嵌套在 `X` 周围的一层括号（如果存在）。例如，`UNPAREN(x)` 和 `UNPAREN((x))` 都展开为 `x`。这在处理带有逗号的模板类型参数时非常有用，可以避免逗号被误解为宏参数分隔符。

**4. 内存布局相关宏:**

*   **`OFFSET_OF(type, field)`:**  等价于标准 C++ 的 `offsetof` 运算符，用于获取结构体或类成员相对于起始地址的偏移量。

**5. 常量定义宏:**

*   **`LITERAL_COMMA`:**  定义一个逗号，用于在宏参数中表示逗号本身，避免被解析为参数分隔符。

**6. 数组大小计算宏:**

*   **`arraysize(array)`:**  计算静态数组的元素个数。它利用一个模板函数 `ArraySizeHelper` 的返回值类型来在编译时推断数组大小。如果传递的是指针，则会导致编译错误。

**7. 类型转换宏:**

*   **`v8::base::bit_cast<Dest, Source>(source)`:**  提供了一种在不同类型之间进行位级别转换的安全方式，类似于 C++20 的 `std::bit_cast`。它有一些编译时检查，确保源类型和目标类型大小相同，并且都是可平凡复制的。

**8. 禁用特性宏:**

*   **`DISALLOW_ASSIGN(TypeName)`:**  显式删除赋值运算符，防止类的对象被赋值。
*   **`DISALLOW_IMPLICIT_CONSTRUCTORS(TypeName)`:**  显式删除默认构造函数、拷贝构造函数和赋值运算符，通常用于只包含静态方法的类。
*   **`MOVE_ONLY_WITH_DEFAULT_CONSTRUCTORS(TypeName)`:**  禁用拷贝构造和拷贝赋值，但提供默认构造、移动构造和移动赋值，适用于只允许移动的类型。
*   **`MOVE_ONLY_NO_DEFAULT_CONSTRUCTOR(TypeName)`:**  禁用拷贝构造和拷贝赋值，只提供移动构造和移动赋值，适用于只允许移动且没有有意义的默认构造的类型。
*   **`DISALLOW_NEW_AND_DELETE()`:**  禁用动态分配（`new` 和 `delete` 运算符），通常用于栈上分配的对象。

**9. 编译器和静态分析器相关宏:**

*   **`V8_USE_ADDRESS_SANITIZER`，`V8_USE_HWADDRESS_SANITIZER`，`V8_USE_MEMORY_SANITIZER`，`V8_USE_UNDEFINED_BEHAVIOR_SANITIZER`，`V8_USE_SAFE_STACK`:**  这些宏用于检测是否启用了特定的编译器或静态分析器特性，例如 AddressSanitizer (ASan)、Hardware-assisted AddressSanitizer (HWASan)、MemorySanitizer (MSan)、UndefinedBehaviorSanitizer (UBSan) 和 SafeStack。
*   **`DISABLE_CFI_PERF`，`DISABLE_CFI_ICALL`:** 用于禁用 Control Flow Integrity (CFI) 的检查，可能出于性能考虑。`DISABLE_CFI_ICALL` 特别用于禁用间接调用检查，因为 JIT 代码的调用可能无法被 CFI 验证。

**10. 函数信息宏:**

*   **`V8_PRETTY_FUNCTION_VALUE_OR(ELSE)`:**  根据编译器，输出美化的函数签名或提供一个备选值 `ELSE`。

**11. 类型特性宏:**

*   **`v8::base::is_trivially_copyable<T>`:**  提供一个编译时常量，指示类型 `T` 是否是可平凡复制的。它对 MSVC 和某些 GCC 版本进行了兼容性处理。
*   **`ASSERT_TRIVIALLY_COPYABLE(T)`，`ASSERT_NOT_TRIVIALLY_COPYABLE(T)`:**  使用 `static_assert` 在编译时断言类型 `T` 是否是可平凡复制的。

**12. 抑制编译器警告宏:**

*   **`v8::base::Use` 和 `USE(...)`:**  用于标记变量为已使用，从而抑制编译器关于未使用变量的警告。

**13. 类型转换辅助宏:**

*   **`implicit_cast<A>(x)`:**  触发从 `x` 到类型 `A` 的隐式转换。适用于低成本复制的类型。

**14. 定义 64 位常量宏:**

*   **`V8_PTR_PREFIX`，`V8PRIxPTR`，`V8PRIdPTR`，`V8PRIuPTR`，`V8_PTR_HEX_DIGITS`，`V8PRIxPTR_FMT`，`V8PRIxPTRDIFF`，`V8PRIdPTRDIFF`，`V8PRIuPTRDIFF`:**  用于定义和格式化 64 位常量，并处理不同编译器和平台上的差异。

**15. 位运算和对齐宏:**

*   **`make_uint64(uint32_t high, uint32_t low)`:**  将两个 32 位整数组合成一个 64 位整数。
*   **`RoundDown(T x, intptr_t m)` 和 `RoundDown<intptr_t m, typename T>(T x)`:**  将 `x` 向下舍入到 `m` 的最接近的倍数。`m` 必须是 2 的幂。
*   **`RoundUp(T x, intptr_t m)` 和 `RoundUp<intptr_t m, typename T>(T x)`:**  将 `x` 向上舍入到 `m` 的最接近的倍数。`m` 必须是 2 的幂。
*   **`IsAligned(T value, U alignment)`:**  检查 `value` 是否按 `alignment` 对齐。
*   **`AlignedAddress(void* address, size_t alignment)`:**  将地址向下舍入到指定的对齐边界。
*   **`RoundUpAddress(void* address, size_t alignment)`:**  将地址向上舍入到指定的对齐边界。

**16. 浮点数边界检查宏:**

*   **`is_inbounds(float_t v)`:**  检查浮点数 `v` 是否在有符号整数类型的可表示范围内。

**17. 共享库导出宏:**

*   **`V8_EXPORT_ENUM`，`V8_EXPORT_PRIVATE`:**  用于在 Windows 和 Linux 上控制符号的导出和导入，用于构建共享库。

**18. 条件编译宏:**

*   **`IF_WASM(V, ...)`，`IF_WASM_DRUMBRAKE(V, ...)`，`IF_WASM_DRUMBRAKE_INSTR_HANDLER(V, ...)`，`IF_TSAN(V, ...)`，`IF_INTL(V, ...)`，`IF_SHADOW_STACK(V, ...)`，`IF_TARGET_ARCH_64_BIT(V, ...)`，`IF_V8_WASM_RANDOM_FUZZERS(V, ...)`，`IF_NO_V8_WASM_RANDOM_FUZZERS(V, ...)`:**  这些宏用于根据不同的编译选项（例如是否启用 WebAssembly、ThreadSanitizer、Internationalization 支持等）来条件性地包含代码。

**19. Google Test 兼容性宏:**

*   **`FRIEND_TEST(test_case_name, test_name)`:**  在 Google 的内部构建系统中禁用 `FRIEND_TEST` 宏。

**如果 `v8/src/base/macros.h` 以 `.tq` 结尾:**

如果 `v8/src/base/macros.h` 以 `.tq` 结尾，那么它**确实是一个 V8 Torque 源代码文件**。Torque 是 V8 使用的一种领域特定语言 (DSL)，用于生成高效的 C++ 代码，特别是用于实现 JavaScript 内置函数和运行时功能。`.tq` 文件经过 Torque 编译器处理后，会生成相应的 C++ 代码。

**与 JavaScript 的功能关系 (及 JavaScript 示例):**

尽管 `macros.h` 是 C++ 代码，但它定义的一些宏直接或间接地影响着 V8 如何执行 JavaScript 代码。

*   **`arraysize`:**  在 V8 的内部实现中，用于定义各种数据结构的大小，例如固定大小的数组。这与 JavaScript 中数组的概念相关，尽管 JavaScript 数组是动态的。
    ```javascript
    // JavaScript 中数组的长度是动态的
    const arr = [1, 2, 3];
    console.log(arr.length); // 输出 3

    // 在 V8 的 C++ 内部，可能使用 arraysize 定义类似结构的大小
    // 这是一个概念性的例子，并非直接对应
    // 例如，表示一个固定大小的属性列表
    // struct PropertyList {
    //   Object* properties[arraysize(固定大小)];
    // };
    ```

*   **`bit_cast`:**  在 V8 的底层实现中，可能用于在不同的数据表示之间进行转换，例如将数字的 IEEE 754 表示转换为整数表示。这与 JavaScript 中数字类型的内部表示有关。
    ```javascript
    // JavaScript 中的数字类型在内部以 IEEE 754 双精度浮点数表示
    const num = 1.5;

    // V8 内部可能使用类似 bit_cast 的操作来访问其二进制表示
    // 这不是一个直接可用的 JavaScript API
    // 例如，将浮点数的位模式解释为整数
    // uint64_t bits = bit_cast<uint64_t>(num);
    ```

*   **`DISALLOW_ASSIGN`，`DISALLOW_IMPLICIT_CONSTRUCTORS`，`MOVE_ONLY_*`:**  这些宏用于管理 V8 内部对象的生命周期和拷贝行为。这影响着 JavaScript 对象的创建、复制和传递方式。虽然 JavaScript 本身有其自己的对象模型和垃圾回收机制，但 V8 的内部实现需要精细地管理内存。
    ```javascript
    // JavaScript 中对象的赋值是引用赋值
    const obj1 = { value: 1 };
    const obj2 = obj1; // obj2 指向 obj1 同一个对象
    obj2.value = 2;
    console.log(obj1.value); // 输出 2

    // V8 的 C++ 内部，某些对象可能被设计为不可拷贝或赋值，
    // 以确保内部状态的一致性。
    // 这类似于 C++ 中使用 DISALLOW_* 宏的效果。
    ```

**代码逻辑推理 (假设输入与输出):**

*   **`CONCAT(prefix_, suffix)`:**
    *   假设输入: `prefix_ = my`, `suffix = Var`
    *   输出: `myVar`

*   **`UNIQUE_IDENTIFIER(local_)`:**
    *   假设 `__COUNTER__` 的当前值为 `5`
    *   输出: `local_5`

*   **`COUNT_MACRO_ARGS(a, b, c)`:**
    *   假设输入: `a, b, c`
    *   输出: `3`

*   **`GET_NTH_ARG(1, x, y, z)`:**
    *   假设输入: `x, y, z`
    *   输出: `y`

*   **`UNPAREN((MyType))`:**
    *   假设输入: `(MyType)`
    *   输出: `MyType`

**用户常见的编程错误 (及示例):**

*   **错误地将指针传递给 `arraysize`:**
    ```c++
    int arr[] = {1, 2, 3, 4, 5};
    int* ptr = arr;
    size_t size = arraysize(ptr); // 编译错误！arraysize 期望的是数组，而不是指针。
    ```
    **说明:** 用户可能错误地认为 `arraysize` 可以计算指针指向的数组的大小。实际上，`arraysize` 只能用于在编译时确定大小的静态数组。对于指针，需要记录数组的大小或使用其他方法。

*   **在宏参数中错误地使用逗号:**
    ```c++
    #define MY_MACRO(type, name) type name

    // 错误的使用，逗号被解析为参数分隔符
    MY_MACRO(std::vector<int, std::allocator<int>>, myVector);

    // 正确的使用，使用 UNPAREN 或 LITERAL_COMMA
    MY_MACRO(UNPAREN(std::vector<int, std::allocator<int>>), myVector);
    // 或者
    #define MY_MACRO_WITH_COMMA(type, name) type name
    MY_MACRO_WITH_COMMA(std::vector<int LITERAL_COMMA std::allocator<int>>, myVector);
    ```
    **说明:** 当宏的参数本身包含逗号时，预处理器可能会错误地将其解析为宏的参数分隔符。使用 `UNPAREN` 或 `LITERAL_COMMA` 可以避免这个问题。

*   **尝试拷贝被 `DISALLOW_ASSIGN` 或 `DISALLOW_IMPLICIT_CONSTRUCTORS` 禁用的对象:**
    ```c++
    class NonCopyable {
     public:
      NonCopyable(int value) : value_(value) {}
      DISALLOW_ASSIGN(NonCopyable);
      DISALLOW_IMPLICIT_CONSTRUCTORS(NonCopyable);
     private:
      int value_;
    };

    NonCopyable obj1(10);
    // NonCopyable obj2 = obj1; // 编译错误！拷贝构造函数被删除。
    // obj2 = obj1;           // 编译错误！赋值运算符被删除。
    ```
    **说明:** 用户可能会尝试拷贝或赋值被显式禁用拷贝或构造的对象。这些宏的目的是防止这些操作，以维护对象的特定属性或生命周期管理。

总而言之，`v8/src/base/macros.h` 是 V8 项目中一个非常重要的头文件，它提供了一系列强大的宏工具，用于简化 C++ 代码编写、提高代码质量和进行编译时检查，这些都对 V8 引擎的性能和稳定性至关重要。

Prompt: 
```
这是目录为v8/src/base/macros.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/base/macros.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_BASE_MACROS_H_
#define V8_BASE_MACROS_H_

#include <limits>
#include <type_traits>

#include "include/v8config.h"
#include "src/base/compiler-specific.h"
#include "src/base/logging.h"

// No-op macro which is used to work around MSVC's funky VA_ARGS support.
#define EXPAND(X) X

// This macro does nothing. That's all.
#define NOTHING(...)

#define CONCAT_(a, ...) a##__VA_ARGS__
#define CONCAT(a, ...) CONCAT_(a, __VA_ARGS__)
// Creates an unique identifier. Useful for scopes to avoid shadowing names.
#define UNIQUE_IDENTIFIER(base) CONCAT(base, __COUNTER__)

// COUNT_MACRO_ARGS(...) returns the number of arguments passed. Currently, up
// to 8 arguments are supported.
#define COUNT_MACRO_ARGS(...) \
  EXPAND(COUNT_MACRO_ARGS_IMPL(__VA_ARGS__, 8, 7, 6, 5, 4, 3, 2, 1, 0))
#define COUNT_MACRO_ARGS_IMPL(_8, _7, _6, _5, _4, _3, _2, _1, N, ...) N
// GET_NTH_ARG(N, ...) returns the Nth argument in the list of arguments
// following. Currently, up to N=8 is supported.
#define GET_NTH_ARG(N, ...) CONCAT(GET_NTH_ARG_IMPL_, N)(__VA_ARGS__)
#define GET_NTH_ARG_IMPL_0(_0, ...) _0
#define GET_NTH_ARG_IMPL_1(_0, _1, ...) _1
#define GET_NTH_ARG_IMPL_2(_0, _1, _2, ...) _2
#define GET_NTH_ARG_IMPL_3(_0, _1, _2, _3, ...) _3
#define GET_NTH_ARG_IMPL_4(_0, _1, _2, _3, _4, ...) _4
#define GET_NTH_ARG_IMPL_5(_0, _1, _2, _3, _4, _5, ...) _5
#define GET_NTH_ARG_IMPL_6(_0, _1, _2, _3, _4, _5, _6, ...) _6
#define GET_NTH_ARG_IMPL_7(_0, _1, _2, _3, _4, _5, _6, _7, ...) _7

// UNPAREN(x) removes a layer of nested parentheses on x, if any. This means
// that both UNPAREN(x) and UNPAREN((x)) expand to x. This is helpful for macros
// that want to support multi argument templates with commas, e.g.
//
//   #define FOO(Type, Name) UNPAREN(Type) Name;
//
// will work with both
//
//   FOO(int, x);
//   FOO((Foo<int, double, float>), x);
#define UNPAREN(X) CONCAT(DROP_, UNPAREN_ X)
#define UNPAREN_(...) UNPAREN_ __VA_ARGS__
#define DROP_UNPAREN_

#define OFFSET_OF(type, field) offsetof(type, field)

// A comma, to be used in macro arguments where it would otherwise be
// interpreted as separator of arguments.
#define LITERAL_COMMA ,

// The arraysize(arr) macro returns the # of elements in an array arr.
// The expression is a compile-time constant, and therefore can be
// used in defining new arrays, for example.  If you use arraysize on
// a pointer by mistake, you will get a compile-time error.
#define arraysize(array) (sizeof(ArraySizeHelper(array)))

// This template function declaration is used in defining arraysize.
// Note that the function doesn't need an implementation, as we only
// use its type.
template <typename T, size_t N>
char (&ArraySizeHelper(T (&array)[N]))[N];

#if !V8_CC_MSVC
// That gcc wants both of these prototypes seems mysterious. VC, for
// its part, can't decide which to use (another mystery). Matching of
// template overloads: the final frontier.
template <typename T, size_t N>
char (&ArraySizeHelper(const T (&array)[N]))[N];
#endif

// This is an equivalent to C++20's std::bit_cast<>(), but with additional
// warnings. It morally does what `*reinterpret_cast<Dest*>(&source)` does, but
// the cast/deref pair is undefined behavior, while bit_cast<>() isn't.
//
// This is not a magic "get out of UB free" card. This must only be used on
// values, not on references or pointers. For pointers, use
// reinterpret_cast<>(), or static_cast<>() when casting between void* and other
// pointers, and then look at https://eel.is/c++draft/basic.lval#11 as that's
// probably UB also.
namespace v8::base {

template <class Dest, class Source>
V8_INLINE Dest bit_cast(Source const& source) {
  static_assert(!std::is_pointer_v<Source>,
                "bit_cast must not be used on pointer types");
  static_assert(!std::is_pointer_v<Dest>,
                "bit_cast must not be used on pointer types");
  static_assert(!std::is_reference_v<Dest>,
                "bit_cast must not be used on reference types");
  static_assert(
      sizeof(Dest) == sizeof(Source),
      "bit_cast requires source and destination types to be the same size");
  static_assert(std::is_trivially_copyable_v<Source>,
                "bit_cast requires the source type to be trivially copyable");
  static_assert(
      std::is_trivially_copyable_v<Dest>,
      "bit_cast requires the destination type to be trivially copyable");

#if V8_HAS_BUILTIN_BIT_CAST
  return __builtin_bit_cast(Dest, source);
#else
  Dest dest;
  memcpy(&dest, &source, sizeof(dest));
  return dest;
#endif
}

}  // namespace v8::base

// Explicitly declare the assignment operator as deleted.
// Note: This macro is deprecated and will be removed soon. Please explicitly
// delete the assignment operator instead.
#define DISALLOW_ASSIGN(TypeName) TypeName& operator=(const TypeName&) = delete

// Explicitly declare all implicit constructors as deleted, namely the
// default constructor, copy constructor and operator= functions.
// This is especially useful for classes containing only static methods.
#define DISALLOW_IMPLICIT_CONSTRUCTORS(TypeName) \
  TypeName() = delete;                           \
  TypeName(const TypeName&) = delete;            \
  DISALLOW_ASSIGN(TypeName)

// Disallow copying a type, but provide default construction, move construction
// and move assignment. Especially useful for move-only structs.
#define MOVE_ONLY_WITH_DEFAULT_CONSTRUCTORS(TypeName) \
  TypeName() = default;                               \
  MOVE_ONLY_NO_DEFAULT_CONSTRUCTOR(TypeName)

// Disallow copying a type, and only provide move construction and move
// assignment. Especially useful for move-only structs.
#define MOVE_ONLY_NO_DEFAULT_CONSTRUCTOR(TypeName)       \
  TypeName(TypeName&&) V8_NOEXCEPT = default;            \
  TypeName& operator=(TypeName&&) V8_NOEXCEPT = default; \
  TypeName(const TypeName&) = delete;                    \
  DISALLOW_ASSIGN(TypeName)

// A macro to disallow the dynamic allocation.
// This should be used in the private: declarations for a class
// Declaring operator new and delete as deleted is not spec compliant.
// Extract from 3.2.2 of C++11 spec:
//  [...] A non-placement deallocation function for a class is
//  odr-used by the definition of the destructor of that class, [...]
#define DISALLOW_NEW_AND_DELETE()                                \
  void* operator new(size_t) { v8::base::OS::Abort(); }          \
  void* operator new[](size_t) { v8::base::OS::Abort(); }        \
  void operator delete(void*, size_t) { v8::base::OS::Abort(); } \
  void operator delete[](void*, size_t) { v8::base::OS::Abort(); }

// Define V8_USE_ADDRESS_SANITIZER macro.
#if defined(__has_feature)
#if __has_feature(address_sanitizer)
#define V8_USE_ADDRESS_SANITIZER 1
#endif
#endif

// Define V8_USE_HWADDRESS_SANITIZER macro.
#if defined(__has_feature)
#if __has_feature(hwaddress_sanitizer)
#define V8_USE_HWADDRESS_SANITIZER 1
#endif
#endif

// Define V8_USE_MEMORY_SANITIZER macro.
#if defined(__has_feature)
#if __has_feature(memory_sanitizer)
#define V8_USE_MEMORY_SANITIZER 1
#endif
#endif

// Define V8_USE_UNDEFINED_BEHAVIOR_SANITIZER macro.
#if defined(__has_feature)
#if __has_feature(undefined_behavior_sanitizer)
#define V8_USE_UNDEFINED_BEHAVIOR_SANITIZER 1
#endif
#endif

// Define V8_USE_SAFE_STACK macro.
#if defined(__has_feature)
#if __has_feature(safe_stack)
#define V8_USE_SAFE_STACK 1
#endif  // __has_feature(safe_stack)
#endif  // defined(__has_feature)

// DISABLE_CFI_PERF -- Disable Control Flow Integrity checks for Perf reasons.
#define DISABLE_CFI_PERF V8_CLANG_NO_SANITIZE("cfi")

// DISABLE_CFI_ICALL -- Disable Control Flow Integrity indirect call checks,
// useful because calls into JITed code can not be CFI verified. Same for
// UBSan's function pointer type checks.
#ifdef V8_OS_WIN
// On Windows, also needs __declspec(guard(nocf)) for CFG.
#define DISABLE_CFI_ICALL           \
  V8_CLANG_NO_SANITIZE("cfi-icall") \
  V8_CLANG_NO_SANITIZE("function")  \
  __declspec(guard(nocf))
#else
#define DISABLE_CFI_ICALL           \
  V8_CLANG_NO_SANITIZE("cfi-icall") \
  V8_CLANG_NO_SANITIZE("function")
#endif

// V8_PRETTY_FUNCTION_VALUE_OR(ELSE) emits a pretty function value, if
// available for this compiler, otherwise it emits ELSE.
#if defined(V8_CC_GNU)
#define V8_PRETTY_FUNCTION_VALUE_OR(ELSE) __PRETTY_FUNCTION__
#elif defined(V8_CC_MSVC)
#define V8_PRETTY_FUNCTION_VALUE_OR(ELSE) __FUNCSIG__
#else
#define V8_PRETTY_FUNCTION_VALUE_OR(ELSE) ELSE
#endif

namespace v8 {
namespace base {

// Note that some implementations of std::is_trivially_copyable mandate that at
// least one of the copy constructor, move constructor, copy assignment or move
// assignment is non-deleted, while others do not. Be aware that also
// base::is_trivially_copyable will differ for these cases.
template <typename T>
struct is_trivially_copyable {
#if V8_CC_MSVC || (__GNUC__ == 12 && __GNUC_MINOR__ <= 2)
  // Unfortunately, MSVC 2015 is broken in that std::is_trivially_copyable can
  // be false even though it should be true according to the standard.
  // (status at 2018-02-26, observed on the msvc waterfall bot).
  // Interestingly, the lower-level primitives used below are working as
  // intended, so we reimplement this according to the standard.
  // See also https://developercommunity.visualstudio.com/content/problem/
  //          170883/msvc-type-traits-stdis-trivial-is-bugged.html.
  //
  // GCC 12.1 and 12.2 are broken too, they are shipped by some stable Linux
  // distributions, so the same polyfill is also used.
  // See
  // https://gcc.gnu.org/git/?p=gcc.git;a=commitdiff;h=aeba3e009b0abfccaf01797556445dbf891cc8dc
  static constexpr bool value =
      // Copy constructor is trivial or deleted.
      (std::is_trivially_copy_constructible<T>::value ||
       !std::is_copy_constructible<T>::value) &&
      // Copy assignment operator is trivial or deleted.
      (std::is_trivially_copy_assignable<T>::value ||
       !std::is_copy_assignable<T>::value) &&
      // Move constructor is trivial or deleted.
      (std::is_trivially_move_constructible<T>::value ||
       !std::is_move_constructible<T>::value) &&
      // Move assignment operator is trivial or deleted.
      (std::is_trivially_move_assignable<T>::value ||
       !std::is_move_assignable<T>::value) &&
      // (Some implementations mandate that one of the above is non-deleted, but
      // the standard does not, so let's skip this check.)
      // Trivial non-deleted destructor.
      std::is_trivially_destructible<T>::value;
#else
  static constexpr bool value = std::is_trivially_copyable<T>::value;
#endif
};
#define ASSERT_TRIVIALLY_COPYABLE(T)                         \
  static_assert(::v8::base::is_trivially_copyable<T>::value, \
                #T " should be trivially copyable")
#define ASSERT_NOT_TRIVIALLY_COPYABLE(T)                      \
  static_assert(!::v8::base::is_trivially_copyable<T>::value, \
                #T " should not be trivially copyable")

// The USE(x, ...) template is used to silence C++ compiler warnings
// issued for (yet) unused variables (typically parameters).
// The arguments are guaranteed to be evaluated from left to right.
struct Use {
  template <typename T>
  constexpr Use(T&&) {}  // NOLINT(runtime/explicit)
};
#define USE(...)                                                   \
  do {                                                             \
    ::v8::base::Use unused_tmp_array_for_use_macro[]{__VA_ARGS__}; \
    (void)unused_tmp_array_for_use_macro;                          \
  } while (false)

}  // namespace base
}  // namespace v8

// implicit_cast<A>(x) triggers an implicit cast from {x} to type {A}. This is
// useful in situations where static_cast<A>(x) would do too much.
// Only use this for cheap-to-copy types, or use move semantics explicitly.
template <class A>
V8_INLINE A implicit_cast(A x) {
  return x;
}

// Define our own macros for writing 64-bit constants.  This is less fragile
// than defining __STDC_CONSTANT_MACROS before including <stdint.h>, and it
// works on compilers that don't have it (like MSVC).
#if V8_CC_MSVC
# if V8_HOST_ARCH_64_BIT
#  define V8_PTR_PREFIX   "ll"
# else
#  define V8_PTR_PREFIX   ""
# endif  // V8_HOST_ARCH_64_BIT
#elif V8_CC_MINGW64
# define V8_PTR_PREFIX    "I64"
#elif V8_HOST_ARCH_64_BIT
# define V8_PTR_PREFIX    "l"
#else
#if V8_OS_AIX
#define V8_PTR_PREFIX "l"
#else
# define V8_PTR_PREFIX    ""
#endif
#endif

#define V8PRIxPTR V8_PTR_PREFIX "x"
#define V8PRIdPTR V8_PTR_PREFIX "d"
#define V8PRIuPTR V8_PTR_PREFIX "u"

#if V8_TARGET_ARCH_64_BIT
#define V8_PTR_HEX_DIGITS 12
#define V8PRIxPTR_FMT "0x%012" V8PRIxPTR
#else
#define V8_PTR_HEX_DIGITS 8
#define V8PRIxPTR_FMT "0x%08" V8PRIxPTR
#endif

// ptrdiff_t is 't' according to the standard, but MSVC uses 'I'.
#if V8_CC_MSVC
#define V8PRIxPTRDIFF "Ix"
#define V8PRIdPTRDIFF "Id"
#define V8PRIuPTRDIFF "Iu"
#else
#define V8PRIxPTRDIFF "tx"
#define V8PRIdPTRDIFF "td"
#define V8PRIuPTRDIFF "tu"
#endif

// Fix for Mac OS X defining uintptr_t as "unsigned long":
#if V8_OS_DARWIN
#undef V8PRIxPTR
#define V8PRIxPTR "lx"
#undef V8PRIdPTR
#define V8PRIdPTR "ld"
#undef V8PRIuPTR
#define V8PRIuPTR "lxu"
#endif

// Make a uint64 from two uint32_t halves.
inline uint64_t make_uint64(uint32_t high, uint32_t low) {
  return (uint64_t{high} << 32) + low;
}

// Return the largest multiple of m which is <= x.
template <typename T>
constexpr T RoundDown(T x, intptr_t m) {
  static_assert(std::is_integral<T>::value);
  // m must be a power of two.
  DCHECK(m != 0 && ((m & (m - 1)) == 0));
  return x & static_cast<T>(-m);
}
template <intptr_t m, typename T>
constexpr T RoundDown(T x) {
  static_assert(std::is_integral<T>::value);
  // m must be a power of two.
  static_assert(m != 0 && ((m & (m - 1)) == 0));
  return x & static_cast<T>(-m);
}

// Return the smallest multiple of m which is >= x.
template <typename T>
constexpr T RoundUp(T x, intptr_t m) {
  static_assert(std::is_integral<T>::value);
  DCHECK_GE(x, 0);
  DCHECK_GE(std::numeric_limits<T>::max() - x, m - 1);  // Overflow check.
  return RoundDown<T>(static_cast<T>(x + (m - 1)), m);
}

template <intptr_t m, typename T>
constexpr T RoundUp(T x) {
  static_assert(std::is_integral<T>::value);
  DCHECK_GE(x, 0);
  DCHECK_GE(std::numeric_limits<T>::max() - x, m - 1);  // Overflow check.
  return RoundDown<m, T>(static_cast<T>(x + (m - 1)));
}

template <typename T, typename U>
constexpr inline bool IsAligned(T value, U alignment) {
  return (value & (alignment - 1)) == 0;
}

inline void* AlignedAddress(void* address, size_t alignment) {
  return reinterpret_cast<void*>(
      RoundDown(reinterpret_cast<uintptr_t>(address), alignment));
}

inline void* RoundUpAddress(void* address, size_t alignment) {
  return reinterpret_cast<void*>(
      RoundUp(reinterpret_cast<uintptr_t>(address), alignment));
}

// Bounds checks for float to integer conversions, which does truncation. Hence,
// the range of legal values is (min - 1, max + 1).
template <typename int_t, typename float_t, typename biggest_int_t = int64_t>
bool is_inbounds(float_t v) {
  static_assert(sizeof(int_t) < sizeof(biggest_int_t),
                "int_t can't be bounds checked by the compiler");
  constexpr float_t kLowerBound =
      static_cast<float_t>(std::numeric_limits<int_t>::min()) - 1;
  constexpr float_t kUpperBound =
      static_cast<float_t>(std::numeric_limits<int_t>::max()) + 1;
  constexpr bool kLowerBoundIsMin =
      static_cast<biggest_int_t>(kLowerBound) ==
      static_cast<biggest_int_t>(std::numeric_limits<int_t>::min());
  constexpr bool kUpperBoundIsMax =
      static_cast<biggest_int_t>(kUpperBound) ==
      static_cast<biggest_int_t>(std::numeric_limits<int_t>::max());
  // Using USE(var) is only a workaround for a GCC 8.1 bug.
  USE(kLowerBoundIsMin);
  USE(kUpperBoundIsMax);
  return (kLowerBoundIsMin ? (kLowerBound <= v) : (kLowerBound < v)) &&
         (kUpperBoundIsMax ? (v <= kUpperBound) : (v < kUpperBound));
}

#ifdef V8_OS_WIN

// Setup for Windows shared library export.
#define V8_EXPORT_ENUM
#ifdef BUILDING_V8_SHARED_PRIVATE
#define V8_EXPORT_PRIVATE __declspec(dllexport)
#elif USING_V8_SHARED_PRIVATE
#define V8_EXPORT_PRIVATE __declspec(dllimport)
#else
#define V8_EXPORT_PRIVATE
#endif  // BUILDING_V8_SHARED

#else  // V8_OS_WIN

// Setup for Linux shared library export.
#if V8_HAS_ATTRIBUTE_VISIBILITY
#ifdef BUILDING_V8_SHARED_PRIVATE
#define V8_EXPORT_PRIVATE __attribute__((visibility("default")))
#define V8_EXPORT_ENUM V8_EXPORT_PRIVATE
#else
#define V8_EXPORT_PRIVATE
#define V8_EXPORT_ENUM
#endif
#else
#define V8_EXPORT_PRIVATE
#define V8_EXPORT_ENUM
#endif

#endif  // V8_OS_WIN

// Defines IF_WASM, to be used in macro lists for elements that should only be
// there if WebAssembly is enabled.
#if V8_ENABLE_WEBASSEMBLY
// EXPAND is needed to work around MSVC's broken __VA_ARGS__ expansion.
#define IF_WASM(V, ...) EXPAND(V(__VA_ARGS__))
#else
#define IF_WASM(V, ...)
#endif  // V8_ENABLE_WEBASSEMBLY

#ifdef V8_ENABLE_DRUMBRAKE
#define IF_WASM_DRUMBRAKE(V, ...) EXPAND(V(__VA_ARGS__))
#else
#define IF_WASM_DRUMBRAKE(V, ...)
#endif  // V8_ENABLE_DRUMBRAKE

#if defined(V8_ENABLE_DRUMBRAKE) && !defined(V8_DRUMBRAKE_BOUNDS_CHECKS)
#define IF_WASM_DRUMBRAKE_INSTR_HANDLER(V, ...) EXPAND(V(__VA_ARGS__))
#else
#define IF_WASM_DRUMBRAKE_INSTR_HANDLER(V, ...)
#endif  // V8_ENABLE_DRUMBRAKE && !V8_DRUMBRAKE_BOUNDS_CHECKS

// Defines IF_TSAN, to be used in macro lists for elements that should only be
// there if TSAN is enabled.
#ifdef V8_IS_TSAN
// EXPAND is needed to work around MSVC's broken __VA_ARGS__ expansion.
#define IF_TSAN(V, ...) EXPAND(V(__VA_ARGS__))
#else
#define IF_TSAN(V, ...)
#endif  // V8_IS_TSAN

// Defines IF_INTL, to be used in macro lists for elements that should only be
// there if INTL is enabled.
#ifdef V8_INTL_SUPPORT
// EXPAND is needed to work around MSVC's broken __VA_ARGS__ expansion.
#define IF_INTL(V, ...) EXPAND(V(__VA_ARGS__))
#else
#define IF_INTL(V, ...)
#endif  // V8_INTL_SUPPORT

// Defines IF_SHADOW_STACK, to be used in macro lists for elements that should
// only be there if CET shadow stack is enabled.
#ifdef V8_ENABLE_CET_SHADOW_STACK
// EXPAND is needed to work around MSVC's broken __VA_ARGS__ expansion.
#define IF_SHADOW_STACK(V, ...) EXPAND(V(__VA_ARGS__))
#else
#define IF_SHADOW_STACK(V, ...)
#endif  // V8_ENABLE_CET_SHADOW_STACK

// Defines IF_TARGET_ARCH_64_BIT, to be used in macro lists for elements that
// should only be there if the target architecture is a 64-bit one.
#if V8_TARGET_ARCH_64_BIT
// EXPAND is needed to work around MSVC's broken __VA_ARGS__ expansion.
#define IF_TARGET_ARCH_64_BIT(V, ...) EXPAND(V(__VA_ARGS__))
#else
#define IF_TARGET_ARCH_64_BIT(V, ...)
#endif  // V8_TARGET_ARCH_64_BIT

// Defines IF_V8_WASM_RANDOM_FUZZERS and IF_NO_V8_WASM_RANDOM_FUZZERS, to be
// used in macro lists for elements that should only be there/absent when
// building the Wasm fuzzers.
#ifdef V8_WASM_RANDOM_FUZZERS
// EXPAND is needed to work around MSVC's broken __VA_ARGS__ expansion.
#define IF_V8_WASM_RANDOM_FUZZERS(V, ...) EXPAND(V(__VA_ARGS__))
#define IF_NO_V8_WASM_RANDOM_FUZZERS(V, ...)
#else
#define IF_V8_WASM_RANDOM_FUZZERS(V, ...)
#define IF_NO_V8_WASM_RANDOM_FUZZERS(V, ...) EXPAND(V(__VA_ARGS__))
#endif  // V8_WASM_RANDOM_FUZZERS

#ifdef GOOGLE3
// Disable FRIEND_TEST macro in Google3.
#define FRIEND_TEST(test_case_name, test_name)
#endif

#endif  // V8_BASE_MACROS_H_

"""

```