Response:
Let's break down the thought process for analyzing this `logging.h` file.

**1. Initial Scan and Identification of Key Areas:**

The first step is to quickly read through the code, looking for obvious patterns and keywords. Things that jump out are:

* `#ifndef V8_BASE_LOGGING_H_`, `#define V8_BASE_LOGGING_H_`, `#endif`:  This is a standard header guard, meaning this file is designed to be included multiple times without causing redefinition errors. It's a core header file.
* `#include <...> `:  Lots of standard C++ library includes (`cstdint`, `cstring`, `sstream`, `string`, `utility`, `vector`, `iterator`). This suggests the file deals with basic data types, string manipulation, and potentially collections.
* `#include "src/base/..."`: Includes from within the V8 project itself (`abort-mode.h`, `base-export.h`, etc.). This points to the file being part of V8's internal infrastructure.
* `V8_BASE_EXPORT`: This macro is used to mark symbols as exported from a shared library. It suggests this file defines functions or data that are intended to be used by other parts of V8.
* `V8_NOINLINE`:  This likely prevents the compiler from inlining the marked functions, probably for debugging purposes or to maintain specific call stack behavior in error scenarios.
* `V8_Dcheck`, `V8_Fatal`:  These look like core logging/assertion functions. The capitalization suggests they are macros or functions provided by V8.
* `#ifdef DEBUG`, `#else`: Conditional compilation. This indicates different behavior depending on whether the code is compiled in debug or release mode.
* `FATAL(...)`, `GRACEFUL_FATAL(...)`: Macros that seem to trigger fatal errors.
* `UNIMPLEMENTED()`, `UNREACHABLE()`: Macros for indicating code paths that should not be reached.
* `namespace v8::base`:  This file belongs to the `v8::base` namespace, which likely contains foundational utilities for the V8 engine.
* `CheckMessageStream`:  A custom stream class for building error messages.
* `SetPrintStackTrace`, `SetDcheckFunction`, `SetFatalFunction`: Functions to override default error handling behavior. This is a strong indicator of a flexible logging system.
* `OOMType`: An enumeration for different out-of-memory scenarios.
* `CHECK(...)`, `DCHECK(...)`, `CHECK_EQ(...)`, etc.:  Assertion macros. `CHECK` is always enabled, `DCHECK` only in debug mode.
* `PrintCheckOperand`: A template function for converting values to strings for error messages. The specializations for different types are interesting.
* `MakeCheckOpString`:  A function to construct detailed error messages for failed checks, including the values being compared.
* `comparison_underlying_type`: A template to get the underlying type of enums or the decayed type for non-enums. This is used for type-safe comparisons.
* `is_signed_vs_unsigned`, `is_unsigned_vs_signed`:  Template structs to detect signed/unsigned mismatches in comparisons.
* `CmpEQImpl`, `CmpNEImpl`, etc.: Template functions providing the actual comparison logic, with special handling for signed/unsigned comparisons.

**2. Grouping Functionalities:**

Based on the initial scan, I start grouping the identified elements into logical functionalities:

* **Basic Logging & Fatal Errors:** `V8_Fatal`, `FATAL`, `GRACEFUL_FATAL`, `UNIMPLEMENTED`, `UNREACHABLE`, `FatalOOM`. This is the core mechanism for reporting critical errors.
* **Assertions (Debug and Release):** `CHECK`, `DCHECK`, `CHECK_WITH_MSG`, `DCHECK_WITH_MSG`, `CHECK_EQ`, `DCHECK_EQ`, etc. These macros verify conditions and report errors if they fail.
* **Customization/Hooks:** `SetPrintStackTrace`, `SetDcheckFunction`, `SetFatalFunction`. This allows external components to customize error handling.
* **Error Message Formatting:** `CheckMessageStream`, `PrintCheckOperand`, `MakeCheckOpString`. This is about creating informative error messages.
* **Internal Utilities for Comparisons:** `comparison_underlying_type`, `is_signed_vs_unsigned`, `CmpEQImpl`, etc. These are helper components for the assertion macros to perform comparisons correctly, especially with potential type mismatches.

**3. Detailed Analysis of Each Functionality:**

For each group, I go back to the code and analyze the details:

* **Logging:**  Note the different `FATAL` behavior in debug vs. release builds. Observe the inclusion of file and line information in debug.
* **Assertions:** Pay attention to the conditional compilation of `DCHECK`. Understand the difference between `CHECK` and `DCHECK`. Analyze the `CHECK_OP` and `DCHECK_OP` macros and how they use the `Cmp...Impl` and `MakeCheckOpString` functions.
* **Customization:** Understand how the setter functions work to replace the default implementations.
* **Error Messages:**  Examine how `PrintCheckOperand` handles different data types (built-in types, enums, containers). See how `MakeCheckOpString` formats the output, including handling long strings.
* **Comparisons:**  Realize the complexity involved in handling comparisons between signed and unsigned integers to avoid unexpected behavior.

**4. Connecting to JavaScript and Torque (as requested):**

* **JavaScript Connection:**  Think about how logging and assertions relate to JavaScript errors. `FATAL` likely corresponds to unrecoverable errors in the V8 engine that would cause the JavaScript execution to stop. `CHECK`/`DCHECK` failures indicate internal inconsistencies within V8. While this header isn't *directly* used in JavaScript code, its behavior has consequences for JavaScript execution. The OOM handling is directly relevant to JavaScript.
* **Torque Connection:** If the file had a `.tq` extension, it would indicate a Torque source file. Torque is V8's internal language. In that case, the logging and assertion mechanisms would be used within Torque code for internal validation. Since it's `.h`, it's a C++ header used by Torque-generated C++.

**5. Generating Examples and Identifying Common Errors:**

* **JavaScript Example:**  Create a simple JavaScript example that would *indirectly* trigger a `FatalOOM` (running out of memory).
* **Code Logic Inference:** Choose a simple `CHECK` macro and demonstrate how different inputs would lead to success or failure.
* **Common Errors:** Focus on mistakes developers make with assertions, such as relying on side effects in release builds or comparing signed and unsigned integers without understanding the potential issues.

**6. Structuring the Output:**

Finally, organize the findings into a clear and structured format, covering the requested aspects: functionalities, JavaScript relevance, Torque relevance, code logic inference, and common programming errors. Use clear headings and concise explanations.

This detailed thought process, moving from a high-level overview to specific details, and focusing on the connections and implications, allows for a comprehensive understanding of the `logging.h` file.
这是一个V8 C++源代码文件，定义了V8引擎中使用的日志和断言机制。虽然它本身不是Torque源代码（`.tq` 结尾的文件才是），但它提供的功能会被V8的各个部分使用，包括由Torque生成的代码。它与JavaScript的功能有间接关系，因为它用于在V8引擎内部进行错误检查和报告，这些错误可能最终影响JavaScript的执行。

以下是 `v8/src/base/logging.h` 的功能列表：

**1. 提供断言机制 (Assertions):**

* **`CHECK(condition)`:**  在所有构建模式下都会执行的断言。如果 `condition` 为假，则会触发致命错误 (FATAL)。用于检查程序运行的必要条件。
* **`DCHECK(condition)`:**  仅在调试 (DEBUG) 构建模式下执行的断言。用于检查开发阶段的假设。在发布版本中会被忽略，以提高性能。
* **`CHECK_WITH_MSG(condition, message)` 和 `DCHECK_WITH_MSG(condition, message)`:**  允许在断言失败时提供自定义错误消息。
* **`CHECK_OP(name, op, lhs, rhs)` 和 `DCHECK_OP(name, op, lhs, rhs)`:**  用于比较操作的断言，例如 `CHECK_EQ` (等于), `CHECK_NE` (不等于), `CHECK_LT` (小于) 等。它们会提供更详细的错误信息，包括比较的左右值。
* **`CHECK_NULL(val)` 和 `DCHECK_NULL(val)`:** 断言指针是否为空。
* **`CHECK_NOT_NULL(val)` 和 `DCHECK_NOT_NULL(val)`:** 断言指针是否非空。
* **`CHECK_IMPLIES(lhs, rhs)` 和 `DCHECK_IMPLIES(lhs, rhs)`:** 断言逻辑蕴含关系。
* **`CHECK_BOUNDS(index, limit)` 和 `DCHECK_BOUNDS(index, limit)`:** 检查索引是否在有效范围内 (0 到 limit-1)。

**2. 提供致命错误报告机制 (Fatal Error Reporting):**

* **`FATAL(...)`:**  报告一个致命错误，导致程序立即终止。在调试模式下，会包含文件名、行号和完整的错误消息。在发布版本中，行为可能有所不同，根据 `OFFICIAL_BUILD` 的定义，可能只包含错误消息或直接调用 `IMMEDIATE_CRASH()`。
* **`GRACEFUL_FATAL(...)`:**  在所有构建模式下都等同于 `FATAL(...)`，目的是为了在某些测试场景下替代 `IMMEDIATE_CRASH()`。
* **`UNIMPLEMENTED()` 和 `UNREACHABLE()`:**  用于标记代码中不应该被执行到的部分。如果执行到这些宏，会触发致命错误。
* **`FatalOOM(OOMType type, const char* msg)`:**  报告内存不足错误，并终止程序。`OOMType` 指示是 JavaScript 堆内存不足还是进程内存不足。

**3. 提供自定义错误处理的接口:**

* **`SetPrintStackTrace(void (*print_stack_trace_)())`:**  允许用户自定义堆栈跟踪的打印函数。
* **`SetDcheckFunction(void (*dcheck_Function)(const char*, int, const char*))`:**  允许用户自定义 `DCHECK` 失败时的处理函数。
* **`SetFatalFunction(void (*fatal_Function)(const char*, int, const char*))`:**  允许用户自定义 `FATAL` 失败时的处理函数。

**4. 定义了一些常量:**

* **`kUnimplementedCodeMessage` 和 `kUnreachableCodeMessage`:**  用于 `UNIMPLEMENTED()` 和 `UNREACHABLE()` 宏的默认错误消息。

**如果 `v8/src/base/logging.h` 以 `.tq` 结尾:**

如果文件名为 `v8/src/base/logging.tq`，那么它就是一个 **V8 Torque 源代码文件**。 Torque 是 V8 内部使用的一种领域特定语言，用于生成高效的 C++ 代码，特别是用于实现 V8 的内置函数和运行时功能。在这种情况下，该文件会使用 Torque 的语法来定义日志和断言相关的逻辑，并最终生成 C++ 代码 (很可能包含当前 `logging.h` 中定义的功能)。

**与 JavaScript 的功能关系 (及 JavaScript 示例):**

`v8/src/base/logging.h` 中定义的机制主要用于 V8 引擎的内部开发和调试。JavaScript 开发者通常不会直接与这些宏交互。然而，这些机制在幕后确保了 V8 引擎的正确性和稳定性，从而间接地影响了 JavaScript 的执行。

例如，如果 V8 引擎在执行 JavaScript 代码时遇到内部错误，`FATAL` 宏可能会被触发，导致 V8 崩溃或抛出错误。 `CHECK` 和 `DCHECK` 用于在开发过程中捕获 V8 内部的逻辑错误，防止这些错误影响到最终的 JavaScript 执行。

**JavaScript 示例 (间接关系):**

```javascript
// 这段 JavaScript 代码可能会间接触发 V8 内部的 OOM (Out Of Memory) 错误
// 从而可能导致 V8 内部调用 FatalOOM

try {
  const hugeArray = [];
  for (let i = 0; i < 1e9; i++) {
    hugeArray.push(i);
  }
} catch (e) {
  console.error("Caught an error:", e);
}
```

在这个例子中，如果 JavaScript 尝试分配一个非常大的数组，导致 JavaScript 堆内存不足，V8 引擎内部可能会调用 `FatalOOM` 来终止进程，或者抛出一个 `OutOfMemoryError` 异常到 JavaScript 代码中。

**代码逻辑推理 (假设输入与输出):**

假设我们有以下 C++ 代码片段使用了 `CHECK` 宏：

```c++
int divide(int a, int b) {
  CHECK(b != 0);
  return a / b;
}

int main() {
  int result = divide(10, 2); // 输入: a = 10, b = 2
  // ...
  int error_result = divide(5, 0); // 输入: a = 5, b = 0
  return 0;
}
```

**假设输入与输出:**

* **输入:** `divide(10, 2)`
* **输出:** 函数返回 `5`。 `CHECK(b != 0)` 条件成立，程序继续执行。

* **输入:** `divide(5, 0)`
* **输出:** 由于 `b` 的值为 `0`，`CHECK(b != 0)` 条件不成立。
    * **调试模式 (DEBUG):**  `FATAL` 宏被调用，输出类似 "Check failed: b != 0. File: your_file.cc, Line: X" 的错误信息，程序终止。
    * **发布模式 (RELEASE):**  根据 `FATAL` 的定义，可能会直接调用 `IMMEDIATE_CRASH()` 或输出简化的错误信息并终止程序。

**用户常见的编程错误 (与 logging.h 相关):**

1. **在发布版本中依赖 `DCHECK` 的副作用:**  `DCHECK` 在发布版本中会被移除，因此不应在 `DCHECK` 的条件表达式中包含任何重要的副作用。

   ```c++
   // 错误示例：在 DCHECK 中调用了会修改状态的函数
   bool isInitialized = false;
   void initialize() { isInitialized = true; }

   void someFunction() {
     DCHECK(initialize()); // 在发布版本中，initialize() 不会被调用
     // ... 依赖于 isInitialized 为 true 的代码 ...
   }
   ```

2. **过度使用 `FATAL`:**  `FATAL` 应该只用于指示程序无法继续运行的严重错误。对于可以恢复的错误，应该使用异常或其他错误处理机制。

3. **忽略 `CHECK` 失败的后果:**  `CHECK` 失败意味着程序的状态违反了预期的必要条件，继续执行可能会导致更严重的问题。应该认真对待 `CHECK` 失败，并修复导致失败的根本原因。

4. **在比较有符号和无符号整数时使用 `CHECK_EQ` 等:**  虽然 `CHECK_OP` 宏通常能处理这种情况，但理解有符号和无符号整数之间的比较规则仍然很重要，以避免潜在的意外行为。

5. **自定义错误处理函数中出现错误:** 如果自定义的 `SetFatalFunction` 或其他错误处理函数本身出现错误，可能会导致程序崩溃或其他不可预测的行为。

总而言之，`v8/src/base/logging.h` 是 V8 引擎中一个至关重要的基础设施文件，它提供了用于诊断、调试和确保代码健壮性的核心机制。虽然 JavaScript 开发者不直接使用它，但它的功能对 V8 的稳定运行和 JavaScript 的正确执行至关重要。

### 提示词
```
这是目录为v8/src/base/logging.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/base/logging.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_BASE_LOGGING_H_
#define V8_BASE_LOGGING_H_

#include <cstdint>
#include <cstring>
#include <iterator>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "src/base/abort-mode.h"
#include "src/base/base-export.h"
#include "src/base/build_config.h"
#include "src/base/compiler-specific.h"
#include "src/base/immediate-crash.h"
#include "src/base/template-utils.h"

V8_BASE_EXPORT V8_NOINLINE void V8_Dcheck(const char* file, int line,
                                          const char* message);

#ifdef DEBUG
// In debug, include file, line, and full error message for all
// FATAL() calls.
[[noreturn]] PRINTF_FORMAT(3, 4) V8_BASE_EXPORT V8_NOINLINE
    void V8_Fatal(const char* file, int line, const char* format, ...);
#define FATAL(...) V8_Fatal(__FILE__, __LINE__, __VA_ARGS__)

// The following can be used instead of FATAL() to prevent calling
// IMMEDIATE_CRASH in official mode. Please only use if needed for testing.
// See v8:13945
#define GRACEFUL_FATAL(...) FATAL(__VA_ARGS__)

#else
[[noreturn]] PRINTF_FORMAT(1, 2) V8_BASE_EXPORT V8_NOINLINE
    void V8_Fatal(const char* format, ...);
#define GRACEFUL_FATAL(...) V8_Fatal(__VA_ARGS__)

#if !defined(OFFICIAL_BUILD)
// In non-official release, include full error message, but drop file & line
// numbers. It saves binary size to drop the |file| & |line| as opposed to just
// passing in "", 0 for them.
#define FATAL(...) V8_Fatal(__VA_ARGS__)
#else
// FATAL(msg) -> IMMEDIATE_CRASH()
// FATAL(msg, ...) -> V8_Fatal(msg, ...)
#define FATAL_HELPER(_7, _6, _5, _4, _3, _2, _1, _0, ...) _0
#define FATAL_DISCARD_ARG(arg) IMMEDIATE_CRASH()
#define FATAL(...)                                                            \
  FATAL_HELPER(__VA_ARGS__, V8_Fatal, V8_Fatal, V8_Fatal, V8_Fatal, V8_Fatal, \
               V8_Fatal, FATAL_DISCARD_ARG)                                   \
  (__VA_ARGS__)
#endif  // !defined(OFFICIAL_BUILD)
#endif  // DEBUG

namespace v8::base {
// These string constants are pattern-matched by fuzzers.
constexpr const char* kUnimplementedCodeMessage = "unimplemented code";
constexpr const char* kUnreachableCodeMessage = "unreachable code";
}  // namespace v8::base

#define UNIMPLEMENTED() FATAL(::v8::base::kUnimplementedCodeMessage)
#define UNREACHABLE() FATAL(::v8::base::kUnreachableCodeMessage)
// g++ versions <= 8 cannot use UNREACHABLE() in a constexpr function.
// TODO(miladfarca): Remove once all compilers handle this properly.
#if defined(__GNUC__) && !defined(__clang__) && (__GNUC__ <= 8)
#define CONSTEXPR_UNREACHABLE() abort()
#else
#define CONSTEXPR_UNREACHABLE() UNREACHABLE()
#endif

namespace v8 {
namespace base {

class CheckMessageStream : public std::ostringstream {};

// Overwrite the default function that prints a stack trace.
V8_BASE_EXPORT void SetPrintStackTrace(void (*print_stack_trace_)());

// Override the default function that handles DCHECKs.
V8_BASE_EXPORT void SetDcheckFunction(void (*dcheck_Function)(const char*, int,
                                                              const char*));

// Override the default function invoked during V8_Fatal.
V8_BASE_EXPORT void SetFatalFunction(void (*fatal_Function)(const char*, int,
                                                            const char*));

enum class OOMType {
  // We ran out of memory in the JavaScript heap.
  kJavaScript,
  // The process ran out of memory.
  kProcess,
};

// A simpler version of V8::FatalProcessOutOfMemory that is available in
// src/base. Will simply terminate the process with an OOM message that is
// recognizes as such by fuzzers and other tooling.
[[noreturn]] V8_BASE_EXPORT void FatalOOM(OOMType type, const char* msg);

// In official builds, assume all check failures can be debugged given just the
// stack trace.
#if !defined(DEBUG) && defined(OFFICIAL_BUILD)
#define CHECK_FAILED_HANDLER(message) FATAL("ignored")
#else
#define CHECK_FAILED_HANDLER(message) FATAL("Check failed: %s.", message)
#endif

// CHECK dies with a fatal error if condition is not true.  It is *not*
// controlled by DEBUG, so the check will be executed regardless of
// compilation mode.
//
// We make sure CHECK et al. always evaluates their arguments, as
// doing CHECK(FunctionWithSideEffect()) is a common idiom.
#define CHECK_WITH_MSG(condition, message) \
  do {                                     \
    if (V8_UNLIKELY(!(condition))) {       \
      CHECK_FAILED_HANDLER(message);       \
    }                                      \
  } while (false)
#define CHECK(condition) CHECK_WITH_MSG(condition, #condition)

#ifdef DEBUG

#define DCHECK_WITH_MSG_AND_LOC(condition, message, loc)                \
  do {                                                                  \
    if (V8_UNLIKELY(!(condition))) {                                    \
      V8_Dcheck(loc.FileName(), static_cast<int>(loc.Line()), message); \
    }                                                                   \
  } while (false)
#define DCHECK_WITH_MSG(condition, message)   \
  do {                                        \
    if (V8_UNLIKELY(!(condition))) {          \
      V8_Dcheck(__FILE__, __LINE__, message); \
    }                                         \
  } while (false)
#define DCHECK_WITH_LOC(condition, loc) \
  DCHECK_WITH_MSG_AND_LOC(condition, #condition, loc)
#define DCHECK(condition) DCHECK_WITH_MSG(condition, #condition)

// Helper macro for binary operators.
// Don't use this macro directly in your code, use CHECK_EQ et al below.
#define CHECK_OP(name, op, lhs, rhs)                                      \
  do {                                                                    \
    if (std::string* _msg = ::v8::base::Check##name##Impl<                \
            typename ::v8::base::pass_value_or_ref<decltype(lhs)>::type,  \
            typename ::v8::base::pass_value_or_ref<decltype(rhs)>::type>( \
            (lhs), (rhs), #lhs " " #op " " #rhs)) {                       \
      FATAL("Check failed: %s.", _msg->c_str());                          \
      delete _msg;                                                        \
    }                                                                     \
  } while (false)

#define DCHECK_OP(name, op, lhs, rhs)                                     \
  do {                                                                    \
    if (std::string* _msg = ::v8::base::Check##name##Impl<                \
            typename ::v8::base::pass_value_or_ref<decltype(lhs)>::type,  \
            typename ::v8::base::pass_value_or_ref<decltype(rhs)>::type>( \
            (lhs), (rhs), #lhs " " #op " " #rhs)) {                       \
      V8_Dcheck(__FILE__, __LINE__, _msg->c_str());                       \
      delete _msg;                                                        \
    }                                                                     \
  } while (false)

#else

// Make all CHECK functions discard their log strings to reduce code
// bloat for official release builds.

#define CHECK_OP(name, op, lhs, rhs)                                         \
  do {                                                                       \
    bool _cmp = ::v8::base::Cmp##name##Impl<                                 \
        typename ::v8::base::pass_value_or_ref<decltype(lhs)>::type,         \
        typename ::v8::base::pass_value_or_ref<decltype(rhs)>::type>((lhs),  \
                                                                     (rhs)); \
    CHECK_WITH_MSG(_cmp, #lhs " " #op " " #rhs);                             \
  } while (false)

#define DCHECK_WITH_MSG(condition, msg) void(0);

#endif

namespace detail {
template <typename... Ts>
std::string PrintToString(Ts&&... ts) {
  CheckMessageStream oss;
  (..., (oss << std::forward<Ts>(ts)));
  return oss.str();
}

template <typename T>
auto GetUnderlyingEnumTypeForPrinting(T val) {
  auto underlying_val = static_cast<std::underlying_type_t<T>>(val);
  // For single-byte enums, return a 16-bit integer to avoid printing the value
  // as a character.
  if constexpr (sizeof(underlying_val) == 1) {
    constexpr bool kIsSigned = std::is_signed_v<decltype(underlying_val)>;
    using int_t = std::conditional_t<kIsSigned, int16_t, uint16_t>;
    return static_cast<int_t>(underlying_val);
  } else {
    return underlying_val;
  }
}

}  // namespace detail

// Define default PrintCheckOperand<T> for non-printable types.
template <typename T>
std::string PrintCheckOperand(T val) {
  return "<unprintable>";
}

// Define PrintCheckOperand<T> for each T which defines operator<< for ostream,
// except types explicitly specialized below.
template <typename T>
  requires(!std::is_function_v<typename std::remove_pointer<T>::type> &&
           !std::is_enum_v<T> && has_output_operator<T, CheckMessageStream>)
std::string PrintCheckOperand(T val) {
  return detail::PrintToString(std::forward<T>(val));
}

// Provide an overload for functions and function pointers. Function pointers
// don't implicitly convert to void* but do implicitly convert to bool, so
// without this function pointers are always printed as 1 or 0. (MSVC isn't
// standards-conforming here and converts function pointers to regular
// pointers, so this is a no-op for MSVC.)
template <typename T>
  requires(std::is_function_v<typename std::remove_pointer_t<T>>)
std::string PrintCheckOperand(T val) {
  return PrintCheckOperand(reinterpret_cast<const void*>(val));
}

// Define PrintCheckOperand<T> for enums.
template <typename T>
  requires(std::is_enum_v<T>)
std::string PrintCheckOperand(T val) {
  std::string int_str =
      detail::PrintToString(detail::GetUnderlyingEnumTypeForPrinting(val));
  if constexpr (has_output_operator<T, CheckMessageStream>) {
    std::string val_str = detail::PrintToString(val);
    // Printing the original enum might have printed a single non-printable
    // character. Ignore it in that case. Also ignore if it printed the same as
    // the integral representation.
    // TODO(clemensb): Can we somehow statically find out if the output operator
    // is the default one, printing the integral value?
    if ((val_str.length() == 1 && !std::isprint(val_str[0])) ||
        val_str == int_str) {
      return int_str;
    }
    return detail::PrintToString(val_str, " (", int_str, ")");
  } else {
    return int_str;
  }
}

// Define PrintCheckOperand<T> for forward iterable containers without an output
// operator.
template <typename T>
  requires(!has_output_operator<T, CheckMessageStream> &&
           requires(T t) {
             { t.begin() } -> std::forward_iterator;
           })
std::string PrintCheckOperand(T container) {
  CheckMessageStream oss;
  oss << "{";
  bool first = true;
  for (const auto& val : container) {
    if (!first) {
      oss << ",";
    } else {
      first = false;
    }
    oss << PrintCheckOperand(val);
  }
  oss << "}";
  return oss.str();
}

// Define specializations for character types, defined in logging.cc.
#define DEFINE_PRINT_CHECK_OPERAND_CHAR(type)                       \
  template <>                                                       \
  V8_BASE_EXPORT std::string PrintCheckOperand<type>(type ch);      \
  template <>                                                       \
  V8_BASE_EXPORT std::string PrintCheckOperand<type*>(type * cstr); \
  template <>                                                       \
  V8_BASE_EXPORT std::string PrintCheckOperand<const type*>(const type* cstr);

DEFINE_PRINT_CHECK_OPERAND_CHAR(char)
DEFINE_PRINT_CHECK_OPERAND_CHAR(signed char)
DEFINE_PRINT_CHECK_OPERAND_CHAR(unsigned char)
#undef DEFINE_PRINT_CHECK_OPERAND_CHAR

// Build the error message string.  This is separate from the "Impl"
// function template because it is not performance critical and so can
// be out of line, while the "Impl" code should be inline. Caller
// takes ownership of the returned string.
template <typename Lhs, typename Rhs>
V8_NOINLINE std::string* MakeCheckOpString(Lhs lhs, Rhs rhs, char const* msg) {
  std::string lhs_str = PrintCheckOperand<Lhs>(lhs);
  std::string rhs_str = PrintCheckOperand<Rhs>(rhs);
  CheckMessageStream ss;
  ss << msg;
  constexpr size_t kMaxInlineLength = 50;
  if (lhs_str.size() <= kMaxInlineLength &&
      rhs_str.size() <= kMaxInlineLength) {
    ss << " (" << lhs_str << " vs. " << rhs_str << ")";
  } else {
    ss << "\n   " << lhs_str << "\n vs.\n   " << rhs_str << "\n";
  }
  return new std::string(ss.str());
}

// Commonly used instantiations of MakeCheckOpString<>. Explicitly instantiated
// in logging.cc.
#define EXPLICIT_CHECK_OP_INSTANTIATION(type)                                \
  extern template V8_BASE_EXPORT std::string* MakeCheckOpString<type, type>( \
      type, type, char const*);                                              \
  extern template V8_BASE_EXPORT std::string PrintCheckOperand<type>(type);

EXPLICIT_CHECK_OP_INSTANTIATION(int)
EXPLICIT_CHECK_OP_INSTANTIATION(long)       // NOLINT(runtime/int)
EXPLICIT_CHECK_OP_INSTANTIATION(long long)  // NOLINT(runtime/int)
EXPLICIT_CHECK_OP_INSTANTIATION(unsigned int)
EXPLICIT_CHECK_OP_INSTANTIATION(unsigned long)       // NOLINT(runtime/int)
EXPLICIT_CHECK_OP_INSTANTIATION(unsigned long long)  // NOLINT(runtime/int)
EXPLICIT_CHECK_OP_INSTANTIATION(void const*)
#undef EXPLICIT_CHECK_OP_INSTANTIATION

// comparison_underlying_type provides the underlying integral type of an enum,
// or std::decay<T>::type if T is not an enum. Booleans are converted to
// "unsigned int", to allow "unsigned int == bool" comparisons.
template <typename T>
struct comparison_underlying_type {
  // std::underlying_type must only be used with enum types, thus use this
  // {Dummy} type if the given type is not an enum.
  enum Dummy {};
  using decay = typename std::decay<T>::type;
  static constexpr bool is_enum = std::is_enum_v<decay>;
  using underlying = typename std::underlying_type<
      typename std::conditional<is_enum, decay, Dummy>::type>::type;
  using type_or_bool =
      typename std::conditional<is_enum, underlying, decay>::type;
  using type = typename std::conditional<std::is_same_v<type_or_bool, bool>,
                                         unsigned int, type_or_bool>::type;
};
// Cast a value to its underlying type
#define MAKE_UNDERLYING(Type, value) \
  static_cast<typename comparison_underlying_type<Type>::type>(value)

// is_signed_vs_unsigned::value is true if both types are integral, Lhs is
// signed, and Rhs is unsigned. False in all other cases.
template <typename Lhs, typename Rhs>
struct is_signed_vs_unsigned {
  using lhs_underlying = typename comparison_underlying_type<Lhs>::type;
  using rhs_underlying = typename comparison_underlying_type<Rhs>::type;
  static constexpr bool value = std::is_integral_v<lhs_underlying> &&
                                std::is_integral_v<rhs_underlying> &&
                                std::is_signed_v<lhs_underlying> &&
                                std::is_unsigned_v<rhs_underlying>;
};
// Same thing, other way around: Lhs is unsigned, Rhs signed.
template <typename Lhs, typename Rhs>
struct is_unsigned_vs_signed : public is_signed_vs_unsigned<Rhs, Lhs> {};

static_assert(!is_signed_vs_unsigned<unsigned, int>::value);
static_assert(is_unsigned_vs_signed<unsigned, int>::value);
static_assert(is_signed_vs_unsigned<int, unsigned>::value);
static_assert(!is_unsigned_vs_signed<int, unsigned>::value);
static_assert(!is_signed_vs_unsigned<unsigned, unsigned>::value);
static_assert(!is_signed_vs_unsigned<int, int>::value);

// Define the default implementation of Cmp##NAME##Impl to be used by
// CHECK##NAME##Impl.
// Note the specializations below for integral types with mismatching
// signedness.
#define DEFINE_CMP_IMPL(NAME, op)                              \
  template <typename Lhs, typename Rhs>                        \
  V8_INLINE constexpr bool Cmp##NAME##Impl(Lhs lhs, Rhs rhs) { \
    return lhs op rhs;                                         \
  }
DEFINE_CMP_IMPL(EQ, ==)
DEFINE_CMP_IMPL(NE, !=)
DEFINE_CMP_IMPL(LE, <=)
DEFINE_CMP_IMPL(LT, <)
DEFINE_CMP_IMPL(GE, >=)
DEFINE_CMP_IMPL(GT, >)
#undef DEFINE_CMP_IMPL

// Specialize the compare functions for signed vs. unsigned comparisons (via the
// `requires` clause).
#define MAKE_UNSIGNED(Type, value)         \
  static_cast<typename std::make_unsigned< \
      typename comparison_underlying_type<Type>::type>::type>(value)
#define DEFINE_SIGNED_MISMATCH_COMP(CHECK, NAME, IMPL)         \
  template <typename Lhs, typename Rhs>                        \
    requires(CHECK<Lhs, Rhs>::value)                           \
  V8_INLINE constexpr bool Cmp##NAME##Impl(Lhs lhs, Rhs rhs) { \
    return IMPL;                                               \
  }
DEFINE_SIGNED_MISMATCH_COMP(is_signed_vs_unsigned, EQ,
                            lhs >= 0 && MAKE_UNSIGNED(Lhs, lhs) ==
                                            MAKE_UNDERLYING(Rhs, rhs))
DEFINE_SIGNED_MISMATCH_COMP(is_signed_vs_unsigned, LT,
                            lhs < 0 || MAKE_UNSIGNED(Lhs, lhs) <
                                           MAKE_UNDERLYING(Rhs, rhs))
DEFINE_SIGNED_MISMATCH_COMP(is_signed_vs_unsigned, LE,
                            lhs <= 0 || MAKE_UNSIGNED(Lhs, lhs) <=
                                            MAKE_UNDERLYING(Rhs, rhs))
DEFINE_SIGNED_MISMATCH_COMP(is_signed_vs_unsigned, NE, !CmpEQImpl(lhs, rhs))
DEFINE_SIGNED_MISMATCH_COMP(is_signed_vs_unsigned, GT, !CmpLEImpl(lhs, rhs))
DEFINE_SIGNED_MISMATCH_COMP(is_signed_vs_unsigned, GE, !CmpLTImpl(lhs, rhs))
DEFINE_SIGNED_MISMATCH_COMP(is_unsigned_vs_signed, EQ, CmpEQImpl(rhs, lhs))
DEFINE_SIGNED_MISMATCH_COMP(is_unsigned_vs_signed, NE, CmpNEImpl(rhs, lhs))
DEFINE_SIGNED_MISMATCH_COMP(is_unsigned_vs_signed, LT, CmpGTImpl(rhs, lhs))
DEFINE_SIGNED_MISMATCH_COMP(is_unsigned_vs_signed, LE, CmpGEImpl(rhs, lhs))
DEFINE_SIGNED_MISMATCH_COMP(is_unsigned_vs_signed, GT, CmpLTImpl(rhs, lhs))
DEFINE_SIGNED_MISMATCH_COMP(is_unsigned_vs_signed, GE, CmpLEImpl(rhs, lhs))
#undef MAKE_UNSIGNED
#undef DEFINE_SIGNED_MISMATCH_COMP

// Define the implementation of Check##NAME##Impl, using Cmp##NAME##Impl defined
// above.
#define DEFINE_CHECK_OP_IMPL(NAME)                                      \
  template <typename Lhs, typename Rhs>                                 \
  V8_INLINE constexpr std::string* Check##NAME##Impl(Lhs lhs, Rhs rhs,  \
                                                     char const* msg) { \
    using LhsPassT = typename pass_value_or_ref<Lhs>::type;             \
    using RhsPassT = typename pass_value_or_ref<Rhs>::type;             \
    bool cmp = Cmp##NAME##Impl<LhsPassT, RhsPassT>(lhs, rhs);           \
    return V8_LIKELY(cmp)                                               \
               ? nullptr                                                \
               : MakeCheckOpString<LhsPassT, RhsPassT>(lhs, rhs, msg);  \
  }
DEFINE_CHECK_OP_IMPL(EQ)
DEFINE_CHECK_OP_IMPL(NE)
DEFINE_CHECK_OP_IMPL(LE)
DEFINE_CHECK_OP_IMPL(LT)
DEFINE_CHECK_OP_IMPL(GE)
DEFINE_CHECK_OP_IMPL(GT)
#undef DEFINE_CHECK_OP_IMPL

// For CHECK_BOUNDS, define to-unsigned conversion helpers.
template <typename T>
constexpr std::make_unsigned_t<T> ToUnsigned(T val) {
  return static_cast<std::make_unsigned_t<T>>(val);
}

#define CHECK_EQ(lhs, rhs) CHECK_OP(EQ, ==, lhs, rhs)
#define CHECK_NE(lhs, rhs) CHECK_OP(NE, !=, lhs, rhs)
#define CHECK_LE(lhs, rhs) CHECK_OP(LE, <=, lhs, rhs)
#define CHECK_LT(lhs, rhs) CHECK_OP(LT, <, lhs, rhs)
#define CHECK_GE(lhs, rhs) CHECK_OP(GE, >=, lhs, rhs)
#define CHECK_GT(lhs, rhs) CHECK_OP(GT, >, lhs, rhs)
#define CHECK_NULL(val) CHECK((val) == nullptr)
#define CHECK_NOT_NULL(val) CHECK((val) != nullptr)
#define CHECK_IMPLIES(lhs, rhs) \
  CHECK_WITH_MSG(!(lhs) || (rhs), #lhs " implies " #rhs)
// Performs a single (unsigned) comparison to check that {index} is
// in range [0, limit).
#define CHECK_BOUNDS(index, limit) \
  CHECK_LT(v8::base::ToUnsigned(index), v8::base::ToUnsigned(limit))

}  // namespace base
}  // namespace v8


// The DCHECK macro is equivalent to CHECK except that it only
// generates code in debug builds.
#ifdef DEBUG
#define DCHECK_EQ(lhs, rhs) DCHECK_OP(EQ, ==, lhs, rhs)
#define DCHECK_NE(lhs, rhs) DCHECK_OP(NE, !=, lhs, rhs)
#define DCHECK_GT(lhs, rhs) DCHECK_OP(GT, >, lhs, rhs)
#define DCHECK_GE(lhs, rhs) DCHECK_OP(GE, >=, lhs, rhs)
#define DCHECK_LT(lhs, rhs) DCHECK_OP(LT, <, lhs, rhs)
#define DCHECK_LE(lhs, rhs) DCHECK_OP(LE, <=, lhs, rhs)
#define DCHECK_NULL(val) DCHECK((val) == nullptr)
#define DCHECK_NOT_NULL(val) DCHECK((val) != nullptr)
#define DCHECK_IMPLIES(lhs, rhs) \
  DCHECK_WITH_MSG(!(lhs) || (rhs), #lhs " implies " #rhs)
#define DCHECK_BOUNDS(index, limit) \
  DCHECK_LT(v8::base::ToUnsigned(index), v8::base::ToUnsigned(limit))
#else
#define DCHECK(condition)      ((void) 0)
#define DCHECK_WITH_LOC(condition, location) ((void)0)
#define DCHECK_WITH_MSG_AND_LOC(condition, message, location) ((void)0)
#define DCHECK_EQ(v1, v2)      ((void) 0)
#define DCHECK_NE(v1, v2)      ((void) 0)
#define DCHECK_GT(v1, v2)      ((void) 0)
#define DCHECK_GE(v1, v2)      ((void) 0)
#define DCHECK_LT(v1, v2)      ((void) 0)
#define DCHECK_LE(v1, v2)      ((void) 0)
#define DCHECK_NULL(val)       ((void) 0)
#define DCHECK_NOT_NULL(val)   ((void) 0)
#define DCHECK_IMPLIES(v1, v2) ((void) 0)
#define DCHECK_BOUNDS(index, limit) ((void)0)
#endif

#endif  // V8_BASE_LOGGING_H_
```