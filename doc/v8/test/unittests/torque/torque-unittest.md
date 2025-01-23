Response:
Let's break down the thought process for analyzing the `torque-unittest.cc` file.

1. **Understand the Context:** The filename `torque-unittest.cc` immediately suggests this file contains unit tests for the Torque compiler. The directory `v8/test/unittests/torque/` reinforces this. Torque, being a V8-specific language, implies these tests will be checking the correctness of the Torque compiler's behavior.

2. **Initial Code Scan (Imports and Namespaces):**
   - `#include ...`:  The includes confirm this is a C++ file. Key inclusions are:
     - `"src/torque/torque-compiler.h"`: This is central to the purpose of the file – it's testing the compiler.
     - `"src/torque/utils.h"`:  Likely contains helper functions for the compiler.
     - `"test/unittests/test-utils.h"`: Standard V8 testing utilities.
     - `"testing/gmock-support.h"`: Indicates Google Mock is being used for assertions and matchers.
   - `namespace v8 { namespace internal { namespace torque { namespace { ... } } } }`:  This confirms the code is within the V8 project, within the internal Torque components, and uses an anonymous namespace for internal utilities.

3. **Core Testing Setup:** The presence of `kTestTorquePrelude`, `TestCompileTorque`, `ExpectSuccessfulCompilation`, and `ExpectFailingCompilation` immediately stand out. These are the building blocks of the tests:
   - `kTestTorquePrelude`: This is a *very* important piece. It's a string containing basic Torque type definitions. This prelude is prepended to the test cases, creating a self-contained testing environment. Recognizing this prelude is crucial to understanding how the tests work.
   - `TestCompileTorque(std::string source)`: This function takes a Torque source string, prepends the prelude, and calls `CompileTorque`. This is the core action being tested.
   - `ExpectSuccessfulCompilation(std::string source)`: This calls `TestCompileTorque` and asserts that there are no compiler error messages.
   - `ExpectFailingCompilation(...)`: This calls `TestCompileTorque` and asserts that there *are* compiler error messages, allowing testing of error conditions. The overloaded versions with matchers indicate more specific error checking.

4. **Test Case Structure:** The `TEST(Torque, ...)` macros reveal the individual test cases. The first argument ("Torque") suggests they are all part of a "Torque" test suite. The second argument is the specific test name.

5. **Analyzing Individual Test Cases (Examples):**  Pick a few representative test cases to understand their intent.
   - `TEST(Torque, Prelude)`:  This is a basic sanity check. Compiling an empty string with the prelude should succeed.
   - `TEST(Torque, StackDeleteRange)`: This test *doesn't* involve the Torque compiler directly. It's testing a utility function (`Stack::DeleteRange`). This is a reminder that unit tests can cover supporting code as well.
   - `TEST(Torque, TypeNamingConventionLintError)`: This test feeds the compiler a Torque snippet with a type named `foo` (lowercase). The `ExpectFailingCompilation` with `HasSubstr("\"foo\"")` indicates it's checking for a lint error related to type naming conventions.
   - `TEST(Torque, ClassDefinition)`: This test compiles a Torque class definition with various field types. The `@export macro` and the macro body that reads and writes the fields suggest it's checking that the compiler can handle different data types within a class.
   - `TEST(Torque, ConditionalFields)`: The `@if` and `@ifnot` decorators indicate preprocessor-like behavior in Torque. This test likely checks that these conditional compilation features work correctly, potentially by ensuring the resulting class layout is as expected. The failing compilation test with "aligned" suggests it's validating memory alignment based on the conditional fields.

6. **Identify Key Functionality (Based on Test Cases):**  By examining the test cases, we can infer the main functionalities being tested:
   - Basic compilation of valid Torque code.
   - Detection of syntax errors.
   - Enforcement of naming conventions (linting).
   - Handling of different data types (primitive and class types).
   - Support for structs and classes.
   - Conditional compilation (`@if`, `@ifnot`).
   - Constexpr evaluation.
   - Handling of unused variables and arguments (linting).
   - Imports.
   - Generic types.
   - Enums.
   - Constant class fields.
   - References.
   - Error handling (try/catch).
   - Bitfields.
   - Implicit parameters.
   - Builtin functions and their `never` return type.

7. **Relate to JavaScript (If Applicable):**  Consider how Torque features relate to JavaScript. Torque is used to implement V8's built-in functions. So, many of the tested features will have corresponding concepts in JavaScript:
   - **Types:** While JavaScript is dynamically typed, Torque works with explicit types, representing the underlying data structures.
   - **Classes:** Torque classes are used to represent JavaScript objects and their internal structures.
   - **Functions/Macros/Builtins:** Torque macros and builtins implement JavaScript functions.
   - **Error Handling:** Torque's `try`/`catch` maps to JavaScript's `try`/`catch`.

8. **Code Logic Inference (Example):** For a test like `TEST(Torque, LetShouldBeConstLintError)`, the logic is:
   - **Input:** A Torque macro where a `let` variable is declared but never reassigned.
   - **Expected Output:** A compiler error message suggesting the use of `const`.

9. **Common Programming Errors:** The tests implicitly highlight potential programming errors in Torque:
   - Incorrect naming conventions.
   - Unused variables/arguments.
   - Using `let` when `const` is appropriate.
   - Type mismatches (demonstrated by failing compilation tests).
   - Incorrect usage of references.
   - Missing `return` statements in functions that are not `never`.

10. **Refine and Organize:**  Finally, organize the findings into a clear and structured answer, grouping related functionalities and providing illustrative examples. Pay attention to the specific questions asked in the prompt.
`v8/test/unittests/torque/torque-unittest.cc` 是一个 V8 源代码文件，它包含了 **Torque 编译器**的单元测试。

**功能列举:**

该文件的主要功能是测试 Torque 编译器的各个方面，确保其能够正确地解析、分析和处理 Torque 源代码。  具体来说，它测试了：

1. **基本语法和类型系统:**
   - 类型声明 (type, extends)
   - 结构体声明 (struct)
   - 类声明 (class, extends, const 字段)
   - 枚举声明 (enum)
   - 泛型类型 (type Foo<T: type>)
   - 联合类型 (type A = B | C)
   - 内建类型 (Smi, HeapObject, int32, bool 等)
   - 类型别名
   - 字面量类型 (IntegerLiteral)

2. **宏和内建函数:**
   - 宏定义 (macro)
   - 内建函数定义 (builtin)
   - 宏和内建函数的调用
   - 泛型宏和内建函数
   - `intrinsic` 声明

3. **控制流:**
   - 顺序执行
   - `typeswitch` 语句
   - `try...catch` 语句 (测试错误处理机制)

4. **作用域和生命周期:**
   - 变量声明 (let, const)
   - 参数传递 (显式和隐式参数)
   - 标签 (labels)

5. **元编程特性:**
   - `@if`, `@ifnot` 条件编译指令

6. **代码风格和 lint 检查:**
   - 命名规范 (类型和结构体名称)
   - 未使用的变量、参数和标签警告
   - `let` 应该用 `const` 的情况

7. **错误处理:**
   - 测试编译器在遇到错误代码时的行为 (例如，类型错误，未定义的变量，语法错误等)
   - 检查错误信息的准确性

8. **特殊特性:**
   - 引用 (&)
   - 位域 (bitfield)
   - `never` 返回类型 (用于表示永不返回的函数)

**关于文件后缀 `.tq`:**

如果 `v8/test/unittests/torque/torque-unittest.cc` 以 `.tq` 结尾，那么它确实会是一个 **v8 Torque 源代码**文件。然而，根据给出的文件名，它是一个 `.cc` 文件，意味着它是 **C++ 源代码**，用于测试 Torque 编译器。  `.tq` 文件是 Torque 语言本身的源文件。

**与 JavaScript 的关系及示例:**

Torque 语言主要用于编写 V8 JavaScript 引擎的 **内置函数** (built-in functions) 和 **运行时代码** (runtime code)。它提供了比 C++ 更高级的抽象，并允许进行静态类型检查，从而提高代码的可靠性和性能。

许多 JavaScript 的核心功能，例如对象创建、属性访问、函数调用、类型转换等，其底层实现都可能涉及到 Torque 代码。

**JavaScript 示例 (体现 Torque 的功能):**

假设在 Torque 中定义了一个函数 `Add(a: Smi, b: Smi): Smi` 用于执行两个小的整数相加。

```torque
// 假设的 Torque 代码
macro Add(a: Smi, b: Smi): Smi {
  return a + b;
}
```

在 JavaScript 中调用这个函数 (实际上是通过 V8 引擎调用其对应的底层 Torque 实现):

```javascript
function testAdd(x, y) {
  return x + y; // 当 x 和 y 是小整数时，V8 可能会调用类似上面 Torque 函数的实现
}

console.log(testAdd(5, 3)); // 输出 8
```

在这个例子中，`testAdd` 函数的 `+` 操作符在某些情况下可能会由 V8 引擎内部的 Torque 代码来实现。 Torque 提供了静态类型 `Smi` (Small Integer)，这在 JavaScript 中是不可见的，但 V8 内部使用它来进行优化。

**代码逻辑推理 (假设输入与输出):**

考虑以下 Torque 测试代码片段：

```c++
TEST(Torque, BasicAddition) {
  ExpectSuccessfulCompilation(R"(
    @export
    macro Add(a: int32, b: int32): int32 {
      return a + b;
    }
  )");
}
```

**假设输入:**  Torque 编译器接收到以下字符串作为输入：

```torque
@export
macro Add(a: int32, b: int32): int32 {
  return a + b;
}
```

**预期输出:**  `ExpectSuccessfulCompilation` 宏会验证 `TestCompileTorque` 函数的返回值，如果编译成功，则没有错误消息。这意味着 Torque 编译器能够正确地解析 `Add` 宏的定义，包括参数类型、返回类型和加法操作。

**涉及用户常见的编程错误 (示例):**

以下是一些可能在 Torque 编程中出现的错误，并且 `torque-unittest.cc` 中的测试用例可能会覆盖这些情况：

1. **类型错误:**

   ```c++
   TEST(Torque, TypeError) {
     ExpectFailingCompilation(R"(
       @export
       macro Add(a: int32, b: Smi): int32 { // 类型不匹配
         return a + b;
       }
     )", HasSubstr("type mismatch"));
   }
   ```

   **JavaScript 对应错误:** 虽然 JavaScript 是动态类型，但在 V8 的 Torque 层，类型错误会被捕获。这类似于 TypeScript 中的类型错误，如果在 TypeScript 中尝试将 `number` 和 `string` 直接相加，TypeScript 编译器会报错。

2. **未使用变量:**

   ```c++
   TEST(Torque, UnusedVariable) {
     ExpectFailingCompilation(R"(
       @export
       macro Foo(x: int32): int32 {
         let y: int32 = 5; // y 未使用
         return x;
       }
     )", HasSubstr("Variable 'y' is never used"));
   }
   ```

   **JavaScript 对应错误:**  一些 JavaScript 代码检查工具 (例如 ESLint) 也会报告未使用的变量，虽然这不是一个运行时错误，但被认为是代码质量问题。

3. **`let` 应该用 `const`:**

   ```c++
   TEST(Torque, LetShouldBeConst) {
     ExpectFailingCompilation(R"(
       @export
       macro Bar(): int32 {
         let z: int32 = 10; // z 的值没有被修改
         return z;
       }
     )", HasSubstr("Use 'const' instead of 'let' for variable 'z'"));
   }
   ```

   **JavaScript 对应错误:**  ESLint 等工具也会建议在变量值不改变时使用 `const`。

总而言之，`v8/test/unittests/torque/torque-unittest.cc` 是一个至关重要的文件，它通过大量的单元测试确保了 V8 引擎中 Torque 编译器的正确性和健壮性，间接地保障了 JavaScript 引擎的稳定运行。 这些测试覆盖了 Torque 语言的各种特性和可能的错误场景。

### 提示词
```
这是目录为v8/test/unittests/torque/torque-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/torque/torque-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <optional>

#include "src/torque/torque-compiler.h"
#include "src/torque/utils.h"
#include "test/unittests/test-utils.h"
#include "testing/gmock-support.h"

namespace v8 {
namespace internal {
namespace torque {

namespace {

// This is a simplified version of the basic Torque type definitions.
// Some class types are replaced by abstact types to keep it self-contained and
// small.
constexpr const char* kTestTorquePrelude = R"(
type void;
type never;

type IntegerLiteral constexpr 'IntegerLiteral';

namespace torque_internal {
  struct Reference<T: type> {
    const object: HeapObject;
    const offset: intptr;
  }
  type ConstReference<T : type> extends Reference<T>;
  type MutableReference<T : type> extends ConstReference<T>;

  type UninitializedHeapObject extends HeapObject;
  macro DownCastForTorqueClass<T : type extends HeapObject>(o: HeapObject):
      T labels _CastError {
    return %RawDownCast<T>(o);
  }
  macro IsWithContext<T : type extends HeapObject>(o: HeapObject): bool {
    return false;
  }
}

type Tagged generates 'TNode<MaybeObject>' constexpr 'MaybeObject';
type StrongTagged extends Tagged
    generates 'TNode<Object>' constexpr 'Object';
type Smi extends StrongTagged generates 'TNode<Smi>' constexpr 'Smi';
type WeakHeapObject extends Tagged;
type Weak<T : type extends HeapObject> extends WeakHeapObject;
type Uninitialized extends Tagged;
type TaggedIndex extends StrongTagged;
type TaggedZeroPattern extends TaggedIndex;

@abstract
@doNotGenerateCppClass
extern class HeapObject extends StrongTagged {
  map: Map;
}
type Map extends HeapObject generates 'TNode<Map>';
type Object = Smi | HeapObject;
type Number = Smi|HeapNumber;
type JSReceiver extends HeapObject generates 'TNode<JSReceiver>';
type JSObject extends JSReceiver generates 'TNode<JSObject>';
type int32 generates 'TNode<Int32T>' constexpr 'int32_t';
type uint32 generates 'TNode<Uint32T>' constexpr 'uint32_t';
type int31 extends int32
    generates 'TNode<Int32T>' constexpr 'int31_t';
type uint31 extends uint32
    generates 'TNode<Uint32T>' constexpr 'uint31_t';
type int16 extends int31
    generates 'TNode<Int16T>' constexpr 'int16_t';
type uint16 extends uint31
    generates 'TNode<Uint16T>' constexpr 'uint16_t';
type int8 extends int16 generates 'TNode<Int8T>' constexpr 'int8_t';
type uint8 extends uint16
    generates 'TNode<Uint8T>' constexpr 'uint8_t';
type int64 generates 'TNode<Int64T>' constexpr 'int64_t';
type intptr generates 'TNode<IntPtrT>' constexpr 'intptr_t';
type uintptr generates 'TNode<UintPtrT>' constexpr 'uintptr_t';
type float32 generates 'TNode<Float32T>' constexpr 'float';
type float64 generates 'TNode<Float64T>' constexpr 'double';
type bool generates 'TNode<BoolT>' constexpr 'bool';
type bint generates 'TNode<BInt>' constexpr 'BInt';
type string constexpr 'const char*';
type RawPtr generates 'TNode<RawPtrT>' constexpr 'void*';
type ExternalPointer
    generates 'TNode<ExternalPointerT>' constexpr 'ExternalPointer_t';
type CppHeapPointer
    generates 'TNode<CppHeapPointerT>' constexpr 'CppHeapPointer_t';
type TrustedPointer
    generates 'TNode<TrustedPointerT>' constexpr 'TrustedPointer_t';
type ProtectedPointer extends Tagged;
type InstructionStream extends HeapObject generates 'TNode<InstructionStream>';
type BuiltinPtr extends Smi generates 'TNode<BuiltinPtr>';
type Context extends HeapObject generates 'TNode<Context>';
type NativeContext extends Context;
type SmiTagged<T : type extends uint31> extends Smi;
type String extends HeapObject;
type HeapNumber extends HeapObject;
type FixedArrayBase extends HeapObject;
type Lazy<T: type>;

struct float64_or_hole {
  is_hole: bool;
  value: float64;
}

extern operator '+' macro IntPtrAdd(intptr, intptr): intptr;
extern operator '!' macro Word32BinaryNot(bool): bool;
extern operator '==' macro Word32Equal(int32, int32): bool;

intrinsic %FromConstexpr<To: type, From: type>(b: From): To;
intrinsic %RawDownCast<To: type, From: type>(x: From): To;
intrinsic %RawConstexprCast<To: type, From: type>(f: From): To;
extern macro SmiConstant(constexpr Smi): Smi;
extern macro TaggedToSmi(Object): Smi
    labels CastError;
extern macro TaggedToHeapObject(Object): HeapObject
    labels CastError;
extern macro Float64SilenceNaN(float64): float64;

extern macro IntPtrConstant(constexpr int31): intptr;
extern macro ConstexprIntegerLiteralToInt32(constexpr IntegerLiteral): constexpr int32;
extern macro SmiFromInt32(int32): Smi;

macro FromConstexpr<To: type, From: type>(o: From): To;
FromConstexpr<Smi, constexpr Smi>(s: constexpr Smi): Smi {
  return SmiConstant(s);
}
FromConstexpr<Smi, constexpr int31>(s: constexpr int31): Smi {
  return %FromConstexpr<Smi>(s);
}
FromConstexpr<intptr, constexpr int31>(i: constexpr int31): intptr {
  return IntPtrConstant(i);
}
FromConstexpr<intptr, constexpr intptr>(i: constexpr intptr): intptr {
  return %FromConstexpr<intptr>(i);
}
extern macro BoolConstant(constexpr bool): bool;
FromConstexpr<bool, constexpr bool>(b: constexpr bool): bool {
  return BoolConstant(b);
}
FromConstexpr<int32, constexpr int31>(i: constexpr int31): int32 {
  return %FromConstexpr<int32>(i);
}
FromConstexpr<int32, constexpr int32>(i: constexpr int32): int32 {
  return %FromConstexpr<int32>(i);
}
FromConstexpr<int32, constexpr IntegerLiteral>(i: constexpr IntegerLiteral): int32 {
  return FromConstexpr<int32>(ConstexprIntegerLiteralToInt32(i));
}
FromConstexpr<Smi, constexpr IntegerLiteral>(i: constexpr IntegerLiteral): Smi {
  return SmiFromInt32(FromConstexpr<int32>(i));
}

macro Cast<A : type extends Object>(implicit context: Context)(o: Object): A
    labels CastError {
  return Cast<A>(TaggedToHeapObject(o) otherwise CastError)
      otherwise CastError;
}
macro Cast<A : type extends HeapObject>(o: HeapObject): A
    labels CastError;
Cast<Smi>(o: Object): Smi
    labels CastError {
  return TaggedToSmi(o) otherwise CastError;
}
)";

TorqueCompilerResult TestCompileTorque(std::string source) {
  TorqueCompilerOptions options;
  options.output_directory = "";
  options.collect_language_server_data = false;
  options.force_assert_statements = false;
  options.v8_root = ".";

  source = kTestTorquePrelude + source;
  return CompileTorque(source, options);
}

void ExpectSuccessfulCompilation(std::string source) {
  TorqueCompilerResult result = TestCompileTorque(std::move(source));
  std::vector<std::string> messages;
  for (const auto& message : result.messages) {
    messages.push_back(message.message);
  }
  EXPECT_EQ(messages, std::vector<std::string>{});
}

template <class T>
using MatcherVector =
    std::vector<std::pair<::testing::PolymorphicMatcher<T>, LineAndColumn>>;

template <class T>
void ExpectFailingCompilation(std::string source,
                              MatcherVector<T> message_patterns) {
  TorqueCompilerResult result = TestCompileTorque(std::move(source));
  ASSERT_FALSE(result.messages.empty());
  EXPECT_GE(result.messages.size(), message_patterns.size());
  size_t limit = message_patterns.size();
  if (result.messages.size() < limit) {
    limit = result.messages.size();
  }
  for (size_t i = 0; i < limit; ++i) {
    EXPECT_THAT(result.messages[i].message, message_patterns[i].first);
    if (message_patterns[i].second != LineAndColumn::Invalid()) {
      std::optional<SourcePosition> actual = result.messages[i].position;
      EXPECT_TRUE(actual.has_value());
      EXPECT_EQ(actual->start, message_patterns[i].second);
    }
  }
}

template <class T>
void ExpectFailingCompilation(
    std::string source, ::testing::PolymorphicMatcher<T> message_pattern) {
  ExpectFailingCompilation(
      source, MatcherVector<T>{{message_pattern, LineAndColumn::Invalid()}});
}

// TODO(almuthanna): the definition of this function is skipped on Fuchsia
// because it causes an 'unused function' exception upon buidling gn
// Ticket: https://crbug.com/1028617
#if !defined(V8_TARGET_OS_FUCHSIA)
int CountPreludeLines() {
  static int result = -1;
  if (result == -1) {
    std::string prelude(kTestTorquePrelude);
    result = static_cast<int>(std::count(prelude.begin(), prelude.end(), '\n'));
  }
  return result;
}
#endif

using SubstrWithPosition =
    std::pair<::testing::PolymorphicMatcher<
                  ::testing::internal::HasSubstrMatcher<std::string>>,
              LineAndColumn>;

// TODO(almuthanna): the definition of this function is skipped on Fuchsia
// because it causes an 'unused function' exception upon buidling gn
// Ticket: https://crbug.com/1028617
#if !defined(V8_TARGET_OS_FUCHSIA)
SubstrWithPosition SubstrTester(const std::string& message, int line, int col) {
  // Change line and column from 1-based to 0-based.
  return {::testing::HasSubstr(message),
          LineAndColumn::WithUnknownOffset(line + CountPreludeLines() - 1,
                                           col - 1)};
}
#endif

using SubstrVector = std::vector<SubstrWithPosition>;

}  // namespace

TEST(Torque, Prelude) { ExpectSuccessfulCompilation(""); }

TEST(Torque, StackDeleteRange) {
  Stack<int> stack = {1, 2, 3, 4, 5, 6, 7};
  stack.DeleteRange(StackRange{BottomOffset{2}, BottomOffset{4}});
  Stack<int> result = {1, 2, 5, 6, 7};
  ASSERT_TRUE(stack == result);
}

using ::testing::HasSubstr;
TEST(Torque, TypeNamingConventionLintError) {
  ExpectFailingCompilation(R"(
    type foo generates 'TNode<Foo>';
  )",
                           HasSubstr("\"foo\""));
}

TEST(Torque, StructNamingConventionLintError) {
  ExpectFailingCompilation(R"(
    struct foo {}
  )",
                           HasSubstr("\"foo\""));
}

TEST(Torque, ClassDefinition) {
  ExpectSuccessfulCompilation(R"(
    extern class TestClassWithAllTypes extends HeapObject {
      a: int8;
      b: uint8;
      b2: uint8;
      b3: uint8;
      c: int16;
      d: uint16;
      e: int32;
      f: uint32;
      g: RawPtr;
      h: intptr;
      i: uintptr;
    }

    @export
    macro TestClassWithAllTypesLoadsAndStores(
        t: TestClassWithAllTypes, r: RawPtr, v1: int8, v2: uint8, v3: int16,
        v4: uint16, v5: int32, v6: uint32, v7: intptr, v8: uintptr): void {
      t.a = v1;
      t.b = v2;
      t.c = v3;
      t.d = v4;
      t.e = v5;
      t.f = v6;
      t.g = r;
      t.h = v7;
      t.i = v8;
      t.a = t.a;
      t.b = t.b;
      t.c = t.c;
      t.d = t.d;
      t.e = t.e;
      t.f = t.f;
      t.g = t.g;
      t.h = t.h;
      t.i = t.i;
    }
  )");
}

TEST(Torque, TypeDeclarationOrder) {
  ExpectSuccessfulCompilation(R"(
    type Baztype = Foo | FooType;

    @abstract
    extern class Foo extends HeapObject {
      fooField: FooType;
    }

    extern class Bar extends Foo {
      barField: Bartype;
      bazfield: Baztype;
    }

    type Bartype = FooType;

    type FooType = Smi | Bar;
  )");
}

// TODO(almuthanna): These tests were skipped because they cause a crash when
// they are ran on Fuchsia. This issue should be solved later on
// Ticket: https://crbug.com/1028617
#if !defined(V8_TARGET_OS_FUCHSIA)
TEST(Torque, ConditionalFields) {
  // This class should throw alignment errors if @if decorators aren't
  // working.
  ExpectSuccessfulCompilation(R"(
  extern class PreprocessingTest extends HeapObject {
    @if(FALSE_FOR_TESTING) a: int8;
    @if(TRUE_FOR_TESTING) a: int16;
    b: int16;
    d: int32;
    @ifnot(TRUE_FOR_TESTING) e: int8;
    @ifnot(FALSE_FOR_TESTING) f: int16;
    g: int16;
    h: int32;
  }
  )");
  ExpectFailingCompilation(R"(
  extern class PreprocessingTest extends HeapObject {
    @if(TRUE_FOR_TESTING) a: int8;
    @if(FALSE_FOR_TESTING) a: int16;
    b: int16;
    d: int32;
    @ifnot(FALSE_FOR_TESTING) e: int8;
    @ifnot(TRUE_FOR_TESTING) f: int16;
    g: int16;
    h: int32;
  }
  )",
                           HasSubstr("aligned"));
}

TEST(Torque, ConstexprLetBindingDoesNotCrash) {
  ExpectFailingCompilation(
      R"(@export macro FooBar(): void { let foo = 0; check(foo >= 0); })",
      HasSubstr("Use 'const' instead of 'let' for variable 'foo'"));
}

TEST(Torque, FailedImplicitCastFromConstexprDoesNotCrash) {
  ExpectFailingCompilation(
      R"(
    extern enum SomeEnum {
      kValue,
      ...
    }
    macro Foo(): void {
      Bar(SomeEnum::kValue);
    }
    macro Bar<T: type>(value: T): void {}
  )",
      HasSubstr(
          "Cannot find non-constexpr type corresponding to constexpr kValue"));
}

TEST(Torque, DoubleUnderScorePrefixIllegalForIdentifiers) {
  ExpectFailingCompilation(R"(
    @export macro Foo(): void {
      let __x;
    }
  )",
                           HasSubstr("Lexer Error"));
}
#endif

TEST(Torque, UnusedLetBindingLintError) {
  ExpectFailingCompilation(R"(
    @export macro Foo(y: Smi): void {
      let x: Smi = y;
    }
  )",
                           HasSubstr("Variable 'x' is never used."));
}

TEST(Torque, UnderscorePrefixSilencesUnusedWarning) {
  ExpectSuccessfulCompilation(R"(
    @export macro Foo(y: Smi): void {
      let _x: Smi = y;
    }
  )");
}

// TODO(almuthanna): This test was skipped because it causes a crash when it is
// ran on Fuchsia. This issue should be solved later on
// Ticket: https://crbug.com/1028617
#if !defined(V8_TARGET_OS_FUCHSIA)
TEST(Torque, UsingUnderscorePrefixedIdentifierError) {
  ExpectFailingCompilation(R"(
    @export macro Foo(y: Smi): void {
      let _x: Smi = y;
      check(_x == y);
    }
  )",
                           HasSubstr("Trying to reference '_x'"));
}
#endif

TEST(Torque, UnusedArgumentLintError) {
  ExpectFailingCompilation(R"(
    @export macro Foo(x: Smi): void {}
  )",
                           HasSubstr("Variable 'x' is never used."));
}

TEST(Torque, UsingUnderscorePrefixedArgumentSilencesWarning) {
  ExpectSuccessfulCompilation(R"(
    @export macro Foo(_y: Smi): void {}
  )");
}

TEST(Torque, UnusedLabelLintError) {
  ExpectFailingCompilation(R"(
    @export macro Foo(): void labels Bar {}
  )",
                           HasSubstr("Label 'Bar' is never used."));
}

TEST(Torque, UsingUnderScorePrefixLabelSilencesWarning) {
  ExpectSuccessfulCompilation(R"(
    @export macro Foo(): void labels _Bar {}
  )");
}

TEST(Torque, NoUnusedWarningForImplicitArguments) {
  ExpectSuccessfulCompilation(R"(
    @export macro Foo(implicit c: Context, r: JSReceiver)(): void {}
  )");
}

TEST(Torque, NoUnusedWarningForVariablesOnlyUsedInDchecks) {
  ExpectSuccessfulCompilation(R"(
    @export macro Foo(x: bool): void {
      dcheck(x);
    }
  )");
}

// TODO(almuthanna): This test was skipped because it causes a crash when it is
// ran on Fuchsia. This issue should be solved later on
// Ticket: https://crbug.com/1028617
#if !defined(V8_TARGET_OS_FUCHSIA)
TEST(Torque, ImportNonExistentFile) {
  ExpectFailingCompilation(R"(import "foo/bar.tq")",
                           HasSubstr("File 'foo/bar.tq' not found."));
}
#endif

TEST(Torque, LetShouldBeConstLintError) {
  ExpectFailingCompilation(R"(
    @export macro Foo(y: Smi): Smi {
      let x: Smi = y;
      return x;
    })",
                           HasSubstr("Variable 'x' is never assigned to."));
}

TEST(Torque, LetShouldBeConstIsSkippedForStructs) {
  ExpectSuccessfulCompilation(R"(
    struct Foo{ a: Smi; }
    @export macro Bar(x: Smi): Foo {
      let foo = Foo{a: x};
      return foo;
    }
  )");
}

// TODO(almuthanna): These tests were skipped because they cause a crash when
// they are ran on Fuchsia. This issue should be solved later on
// Ticket: https://crbug.com/1028617
#if !defined(V8_TARGET_OS_FUCHSIA)
TEST(Torque, GenericAbstractType) {
  ExpectSuccessfulCompilation(R"(
    type Foo<T: type> extends HeapObject;
    extern macro F1(HeapObject): void;
    macro F2<T: type>(x: Foo<T>): void {
      F1(x);
    }
    @export
    macro F3(a: Foo<Smi>, b: Foo<HeapObject>): void {
      F2(a);
      F2(b);
    }
  )");

  ExpectFailingCompilation(R"(
    type Foo<T: type> extends HeapObject;
    macro F1<T: type>(x: Foo<T>): void {}
    @export
    macro F2(a: Foo<Smi>): void {
      F1<HeapObject>(a);
    })",
                           HasSubstr("cannot find suitable callable"));

  ExpectFailingCompilation(R"(
    type Foo<T: type> extends HeapObject;
    extern macro F1(Foo<HeapObject>): void;
    @export
    macro F2(a: Foo<Smi>): void {
      F1(a);
    })",
                           HasSubstr("cannot find suitable callable"));
}

TEST(Torque, SpecializationRequesters) {
  ExpectFailingCompilation(
      R"(
    macro A<T: type extends HeapObject>(): void {}
    macro B<T: type>(): void {
      A<T>();
    }
    macro C<T: type>(): void {
      B<T>();
    }
    macro D(): void {
      C<Smi>();
    }
  )",
      SubstrVector{
          SubstrTester("cannot find suitable callable", 4, 7),
          SubstrTester("Note: in specialization B<Smi> requested here", 7, 7),
          SubstrTester("Note: in specialization C<Smi> requested here", 10,
                       7)});

  ExpectFailingCompilation(
      R"(
    extern macro RetVal(): Object;
    builtin A<T: type extends HeapObject>(implicit context: Context)(): Object {
      return RetVal();
    }
    builtin B<T: type>(implicit context: Context)(): Object {
      return A<T>();
    }
    builtin C<T: type>(implicit context: Context)(): Object {
      return B<T>();
    }
    builtin D(implicit context: Context)(): Object {
      return C<Smi>();
    }
  )",
      SubstrVector{
          SubstrTester("cannot find suitable callable", 7, 14),
          SubstrTester("Note: in specialization B<Smi> requested here", 10, 14),
          SubstrTester("Note: in specialization C<Smi> requested here", 13,
                       14)});

  ExpectFailingCompilation(
      R"(
    struct A<T: type extends HeapObject> {}
    struct B<T: type> {
      a: A<T>;
    }
    struct C<T: type> {
      b: B<T>;
    }
    struct D {
      c: C<Smi>;
    }
  )",
      SubstrVector{
          SubstrTester("Could not instantiate generic", 4, 10),
          SubstrTester("Note: in specialization B<Smi> requested here", 7, 10),
          SubstrTester("Note: in specialization C<Smi> requested here", 10,
                       10)});

  ExpectFailingCompilation(
      R"(
    macro A<T: type extends HeapObject>(): void {}
    macro B<T: type>(): void {
      A<T>();
    }
    struct C<T: type> {
      macro Method(): void {
        B<T>();
      }
    }
    macro D(_b: C<Smi>): void {}
  )",
      SubstrVector{
          SubstrTester("cannot find suitable callable", 4, 7),
          SubstrTester("Note: in specialization B<Smi> requested here", 8, 9),
          SubstrTester("Note: in specialization C<Smi> requested here", 11,
                       5)});
}
#endif

TEST(Torque, Enums) {
  ExpectSuccessfulCompilation(R"(
    extern enum MyEnum {
      kValue0,
      kValue1,
      @sameEnumValueAs(kValue0) kValue2,
      kValue3
    }
  )");

  ExpectFailingCompilation(R"(
    extern enum MyEmptyEnum {
    }
  )",
                           HasSubstr("unexpected token \"}\""));
}

TEST(Torque, EnumInTypeswitch) {
  ExpectSuccessfulCompilation(R"(
    extern enum MyEnum extends Smi {
      kA,
      kB,
      kC
    }

    @export
    macro Test(implicit context: Context)(v : MyEnum): Smi {
      typeswitch(v) {
        case (MyEnum::kA | MyEnum::kB): {
          return 1;
        }
        case (MyEnum::kC): {
          return 2;
        }
      }
    }
  )");

  ExpectSuccessfulCompilation(R"(
    extern enum MyEnum extends Smi {
      kA,
      kB,
      kC,
      ...
    }

    @export
    macro Test(implicit context: Context)(v : MyEnum): Smi {
      typeswitch(v) {
         case (MyEnum::kC): {
          return 2;
        }
        case (MyEnum::kA | MyEnum::kB): {
          return 1;
        }
       case (MyEnum): {
          return 0;
        }
      }
    }
  )");

  ExpectSuccessfulCompilation(R"(
  extern enum MyEnum extends Smi {
    kA,
    kB,
    kC,
    ...
  }

  @export
  macro Test(implicit context: Context)(b: bool): Smi {
    return b ? MyEnum::kB : MyEnum::kA;
  }
)");
}

TEST(Torque, EnumTypeAnnotations) {
  ExpectSuccessfulCompilation(R"(
    type Type1 extends intptr;
    type Type2 extends intptr;
    extern enum MyEnum extends intptr {
      kValue1: Type1,
      kValue2: Type2,
      kValue3
    }
    @export macro Foo(): void {
      const _a: Type1 = MyEnum::kValue1;
      const _b: Type2 = MyEnum::kValue2;
      const _c: intptr = MyEnum::kValue3;
    }
  )");
}

TEST(Torque, ConstClassFields) {
  ExpectSuccessfulCompilation(R"(
    class Foo extends HeapObject {
      const x: int32;
      y: int32;
    }

    @export
    macro Test(implicit context: Context)(o: Foo, n: int32): void {
      const _x: int32 = o.x;
      o.y = n;
    }
  )");

  ExpectFailingCompilation(R"(
    class Foo extends HeapObject {
      const x: int32;
    }

    @export
    macro Test(implicit context: Context)(o: Foo, n: int32): void {
      o.x = n;
    }
  )",
                           HasSubstr("cannot assign to const value"));

  ExpectSuccessfulCompilation(R"(
    class Foo extends HeapObject {
      s: Bar;
    }
    struct Bar {
      const x: int32;
      y: int32;
    }

    @export
    macro Test(implicit context: Context)(o: Foo, n: int32): void {
      const _x: int32 = o.s.x;
      // Assigning a struct as a value is OK, even when the struct contains
      // const fields.
      o.s = Bar{x: n, y: n};
      o.s.y = n;
    }
  )");

  ExpectFailingCompilation(R"(
    class Foo extends HeapObject {
      const s: Bar;
    }
    struct Bar {
      const x: int32;
      y: int32;
    }

    @export
    macro Test(implicit context: Context)(o: Foo, n: int32): void {
      o.s.y = n;
    }
  )",
                           HasSubstr("cannot assign to const value"));

  ExpectFailingCompilation(R"(
    class Foo extends HeapObject {
      s: Bar;
    }
    struct Bar {
      const x: int32;
      y: int32;
    }

    @export
    macro Test(implicit context: Context)(o: Foo, n: int32): void {
      o.s.x = n;
    }
  )",
                           HasSubstr("cannot assign to const value"));
}

TEST(Torque, References) {
  ExpectSuccessfulCompilation(R"(
    class Foo extends HeapObject {
      const x: int32;
      y: int32;
    }

    @export
    macro Test(implicit context: Context)(o: Foo, n: int32): void {
      const constRefX: const &int32 = &o.x;
      const refY: &int32 = &o.y;
      const constRefY: const &int32 = refY;
      const _x: int32 = *constRefX;
      const _y1: int32 = *refY;
      const _y2: int32 = *constRefY;
      *refY = n;
      let r: const &int32 = constRefX;
      r = constRefY;
    }
  )");

  ExpectFailingCompilation(R"(
    class Foo extends HeapObject {
      const x: int32;
      y: int32;
    }

    @export
    macro Test(implicit context: Context)(o: Foo): void {
      const _refX: &int32 = &o.x;
    }
  )",
                           HasSubstr("cannot use expression of type const "
                                     "&int32 as a value of type &int32"));

  ExpectFailingCompilation(R"(
    class Foo extends HeapObject {
      const x: int32;
      y: int32;
    }

    @export
    macro Test(implicit context: Context)(o: Foo, n: int32): void {
      const constRefX: const &int32 = &o.x;
      *constRefX = n;
    }
  )",
                           HasSubstr("cannot assign to const value"));
}

TEST(Torque, CatchFirstHandler) {
  ExpectFailingCompilation(
      R"(
    @export
    macro Test(): void {
      try {
      } label Foo {
      } catch (_e, _m) {}
    }
  )",
      HasSubstr(
          "catch handler always has to be first, before any label handler"));
}

TEST(Torque, BitFieldLogicalAnd) {
  std::string prelude = R"(
    bitfield struct S extends uint32 {
      a: bool: 1 bit;
      b: bool: 1 bit;
      c: int32: 5 bit;
    }
    macro Test(s: S): bool { return
  )";
  std::string postlude = ";}";
  std::string message = "use & rather than &&";
  ExpectFailingCompilation(prelude + "s.a && s.b" + postlude,
                           HasSubstr(message));
  ExpectFailingCompilation(prelude + "s.a && !s.b" + postlude,
                           HasSubstr(message));
  ExpectFailingCompilation(prelude + "!s.b && s.c == 34" + postlude,
                           HasSubstr(message));
}

TEST(Torque, FieldAccessOnNonClassType) {
  ExpectFailingCompilation(
      R"(
    @export
    macro Test(x: Number): Map {
      return x.map;
    }
  )",
      HasSubstr("map"));
}

TEST(Torque, UnusedImplicit) {
  ExpectSuccessfulCompilation(R"(
    @export
    macro Test1(implicit c: Smi)(a: Object): Object { return a; }
    @export
    macro Test2(b: Object): void { Test1(b);  }
  )");

  ExpectFailingCompilation(
      R"(
    macro Test1(implicit c: Smi)(_a: Object): Smi { return c; }
    @export
    macro Test2(b: Smi): void { Test1(b);  }
  )",
      HasSubstr("undefined expression of type Smi: the implicit "
                "parameter 'c' is not defined when invoking Test1 at"));

  ExpectFailingCompilation(
      R"(
    extern macro Test3(implicit c: Smi)(Object): Smi;
    @export
    macro Test4(b: Smi): void { Test3(b);  }
  )",
      HasSubstr("unititialized implicit parameters can only be passed to "
                "Torque-defined macros: the implicit parameter 'c' is not "
                "defined when invoking Test3"));
  ExpectSuccessfulCompilation(
      R"(
    macro Test7<T: type>(implicit c: Smi)(o: T): Smi;
    Test7<Smi>(implicit c: Smi)(o: Smi): Smi { return o; }
    @export
    macro Test8(b: Smi): void { Test7(b); }
  )");

  ExpectFailingCompilation(
      R"(
    macro Test6<T: type>(_o: T): T;
    macro Test6<T: type>(implicit c: T)(_o: T): T {
      return c;
    }
    macro Test7<T: type>(o: T): Smi;
    Test7<Smi>(o: Smi): Smi { return Test6<Smi>(o); }
    @export
    macro Test8(b: Smi): void { Test7(b); }
  )",
      HasSubstr("\nambiguous callable : \n  Test6(Smi)\ncandidates are:\n  "
                "Test6(Smi): Smi\n  Test6(implicit Smi)(Smi): Smi"));
}

TEST(Torque, ImplicitTemplateParameterInference) {
  ExpectSuccessfulCompilation(R"(
    macro Foo(_x: Map): void {}
    macro Foo(_x: Smi): void {}
    macro GenericMacro<T: type>(implicit x: T)(): void {
      Foo(x);
    }
    @export
    macro Test1(implicit x: Smi)(): void { GenericMacro(); }
    @export
    macro Test2(implicit x: Map)(): void { GenericMacro();  }
  )");

  ExpectFailingCompilation(
      R"(
    // Wrap in namespace to avoid redeclaration error.
    namespace foo {
    macro Foo(implicit x: Map)(): void {}
    }
    macro Foo(implicit x: Smi)(): void {}
    namespace foo{
    @export
    macro Test(implicit x: Smi)(): void { Foo(); }
    }
  )",
      HasSubstr("ambiguous callable"));

  ExpectFailingCompilation(
      R"(
    // Wrap in namespace to avoid redeclaration error.
    namespace foo {
    macro Foo(implicit x: Map)(): void {}
    }
    macro Foo(implicit x: Smi)(): void {}
    namespace foo{
    @export
    macro Test(implicit x: Map)(): void { Foo(); }
    }
  )",
      HasSubstr("ambiguous callable"));
}

TEST(Torque, BuiltinReturnsNever) {
  ExpectFailingCompilation(
      "builtin Never(): never {}",
      HasSubstr("control reaches end of builtin, expected return of a value"));
  ExpectFailingCompilation(
      "builtin Never(): never { return 1; }",
      HasSubstr("cannot return from a function with return type never"));
  ExpectFailingCompilation(
      R"(
    extern macro Throw(): never;
    builtin Never(): never {
      Throw();
    }
    builtin CallsNever(): Smi {
      Never();
      return 1;
    }
  )",
      HasSubstr("statement after non-returning statement"));

  ExpectSuccessfulCompilation(
      "extern macro Throw(): never;"
      "builtin Never(): never { Throw(); }");
  ExpectSuccessfulCompilation(R"(
    extern macro Throw(): never;
    builtin Never(implicit c: Context, a: int32)(): never {
      if(a == 1) {
        Throw();
      } else {
        Throw();
      }
    }
  )");
}

}  // namespace torque
}  // namespace internal
}  // namespace v8
```