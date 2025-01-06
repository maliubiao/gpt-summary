Response:
The user wants me to analyze a C++ source code file related to regular expressions in V8.
Specifically, they want to know:
1. **Functionality of the code**: What does this code do?
2. **Torque source**: If the filename ends with `.tq`, is it a Torque file?
3. **Relationship to JavaScript**: Does it relate to JavaScript's regex functionality? If so, provide a JavaScript example.
4. **Code logic and examples**:  Provide examples of code logic with assumed inputs and outputs.
5. **Common programming errors**:  Point out potential user errors.
6. **Summary of functionality**: Provide a concise summary of the code's purpose.

Let's go through the provided code snippet and identify its key components:

- **Test Fixtures (`TEST_F`)**: The code uses Google Test (`TEST_F`) framework, indicating it's a unit test file.
- **`RegExpTest` Class**:  The tests are within the `RegExpTest` class, suggesting these tests focus on regular expression functionality.
- **`MacroAssemblerNative...` Test Cases**: Several test cases start with `MacroAssemblerNative`, hinting at testing the native regular expression macro assembler. This likely involves testing low-level implementations of regex operations.
- **`MacroAssembler...` Test Cases**: Other tests like `MacroAssembler` indicate testing a more general regular expression assembler, potentially bytecode-based.
- **V8 Internal Classes**: The code uses V8 internal classes like `Factory`, `Isolate`, `Zone`, `String`, `Code`, `JSRegExp`, `NativeRegExpMacroAssembler`, and `RegExpBytecodeGenerator`. This confirms it's V8 source code.
- **Assembler Operations**:  Methods like `LoadCurrentCharacter`, `Succeed`, `Fail`, `PushBacktrack`, `AdvanceCurrentPosition`, `CheckNotBackReference`, `CheckNotAtStart`, `WriteCurrentPositionToRegister`, `ReadCurrentPositionFromRegister`, `PushRegister`, `PopRegister`, etc., suggest the code is building and testing the execution of regular expression matching logic at a low level.
- **Execution (`Execute`)**: The `Execute` function is used to run the generated regular expression code against input strings.
- **Assertions (`CHECK_EQ`)**: The code uses `CHECK_EQ` to verify the results of the regex execution.

Based on this analysis:

1. **Functionality**: This code tests the low-level implementation of regular expressions in V8, specifically the `NativeRegExpMacroAssembler` and `RegExpBytecodeGenerator`. It covers various aspects like backtracking, backreferences, start-of-string assertions, case-insensitive matching, register manipulation, and stack overflow scenarios.
2. **Torque Source**: The prompt states that if the filename ends with `.tq`, it's Torque. Since the filename is `regexp-unittest.cc`, it's a C++ file, not a Torque file.
3. **Relationship to JavaScript**:  This code directly relates to how JavaScript's regular expressions are implemented internally in V8. The `JSRegExp` class represents a JavaScript RegExp object.
4. **Code logic and examples**: I can use specific test cases like `MacroAssemblerNativeBacktrack` and `MacroAssemblerNativeBackReferenceLATIN1` to illustrate code logic.
5. **Common programming errors**:  I can relate the tested features to common regex errors in JavaScript.
6. **Summary of functionality**: I can now summarize the functionality based on the individual test cases and the overall purpose of the file.
这是v8源代码文件 `v8/test/unittests/regexp/regexp-unittest.cc` 的一部分，它主要的功能是**测试 V8 引擎中正则表达式的底层实现，特别是 `NativeRegExpMacroAssembler` 和 `RegExpBytecodeGenerator` 这两个组件的功能。**

根据您提供的代码片段，可以观察到以下几个方面：

* **测试 `NativeRegExpMacroAssembler`**:  多个以 `MacroAssemblerNative` 开头的 `TEST_F` 用例，例如 `MacroAssemblerNativeBacktrack`, `MacroAssemblerNativeBackReferenceLATIN1`, `MacroAssemblerNativeBackReferenceUC16`, `MacroAssemblernativeAtStart`, `MacroAssemblerNativeBackRefNoCase`, `MacroAssemblerNativeRegisters`, `MacroAssemblerStackOverflow`, `MacroAssemblerNativeLotsOfRegisters`， 都在测试 `NativeRegExpMacroAssembler` 的不同功能。这个类负责在机器码层面实现正则表达式的匹配逻辑。

* **测试回溯 (Backtrack)**: `MacroAssemblerNativeBacktrack` 测试了正则表达式引擎的回溯机制。

* **测试反向引用 (Back Reference)**: `MacroAssemblerNativeBackReferenceLATIN1` 和 `MacroAssemblerNativeBackReferenceUC16` 测试了反向引用的功能，分别针对 LATIN1 和 UC16 编码的字符串。

* **测试 `^` 匹配开头**: `MacroAssemblernativeAtStart` 测试了正则表达式中 `^` 符号（匹配字符串开头）的行为。

* **测试不区分大小写的反向引用**: `MacroAssemblerNativeBackRefNoCase` 测试了不区分大小写的反向引用匹配。

* **测试寄存器操作**: `MacroAssemblerNativeRegisters` 测试了在正则表达式匹配过程中使用寄存器来存储和操作中间状态的功能。

* **测试栈溢出**: `MacroAssemblerStackOverflow` 旨在测试当正则表达式导致过多的回溯时，是否会发生栈溢出。

* **测试大量寄存器使用**: `MacroAssemblerNativeLotsOfRegisters` 测试了分配和使用大量寄存器的情况。

* **测试 `RegExpBytecodeGenerator`**: `MacroAssembler` 这个 `TEST_F` 用例测试了 `RegExpBytecodeGenerator`，这是一个生成正则表达式字节码的组件，用于解释执行。

**如果 `v8/test/unittests/regexp/regexp-unittest.cc` 以 `.tq` 结尾，那它将是一个 v8 Torque 源代码。**  但正如其当前的文件名所示，它以 `.cc` 结尾，因此它是一个 C++ 源代码文件。 Torque 是一种 V8 使用的类型化的中间语言，用于实现一些性能关键的代码。

**这段代码与 javascript 的功能有关系，因为它测试了 javascript 中正则表达式的底层实现。**

**JavaScript 示例：**

与 `MacroAssemblerNativeBackReferenceLATIN1` 测试用例相关的 JavaScript 正则表达式功能是反向引用。

```javascript
const regex = /^(..)..\1/;
const str1 = "fooofo";
const result1 = regex.exec(str1);
console.log(result1); // 输出: ["fooofo", "fo", index: 0, input: "fooofo", groups: undefined]

const str2 = "fooxfo";
const result2 = regex.exec(str2);
console.log(result2); // 输出: null
```

在这个例子中，`\1` 是一个反向引用，它匹配前面第一个捕获组 `(..)` 匹配到的内容。在 `str1` 中，第一个捕获组匹配到 "fo"，因此 `\1` 也需要匹配 "fo"，最终匹配成功。在 `str2` 中，第一个捕获组匹配到 "fo"，但 `\1` 需要匹配 "xf"，所以匹配失败。

**代码逻辑推理 (以 `MacroAssemblerNativeBacktrack` 为例):**

**假设输入字符串为 "foofoo"。**

1. `m.LoadCurrentCharacter(10, &fail);`: 尝试加载当前位置后 10 个字符的字符。由于输入字符串长度为 6，这将会超出范围，因此跳转到 `fail` 标签。
2. `m.BindJumpTarget(&fail);`:  绑定 `fail` 标签。
3. `m.PushBacktrack(&backtrack);`: 将 `backtrack` 标签压入回溯栈。
4. `m.LoadCurrentCharacter(10, nullptr);`:  再次尝试加载当前位置后 10 个字符的字符。这次没有提供失败跳转目标，意味着如果加载失败，执行会继续。
5. `m.Succeed();`:  声明匹配成功。  **这里存在一个逻辑上的矛盾，因为前面的 `LoadCurrentCharacter` 应该会失败。 这可能是为了测试在特定条件下的回溯行为。**
6. `m.BindJumpTarget(&backtrack);`: 绑定 `backtrack` 标签。
7. `m.Fail();`:  声明匹配失败。

**输出:**  由于初始的 `LoadCurrentCharacter` 失败并跳转到 `fail`，然后将 `backtrack` 压栈，但是后续的逻辑并没有明确触发回溯，最终 `Execute` 函数应该返回 `NativeRegExpMacroAssembler::FAILURE`，正如 `CHECK_EQ(NativeRegExpMacroAssembler::FAILURE, result);` 所验证的。

**涉及用户常见的编程错误：**

与反向引用相关的常见编程错误是 **错误地理解反向引用的匹配内容**。反向引用匹配的是**之前捕获组实际匹配到的文本**，而不是与捕获组的模式相同的文本。

**例如：**

```javascript
const regex = /(.)(.)\2\1/;
const str1 = "abba";
const result1 = regex.exec(str1);
console.log(result1); // 输出: ["abba", "a", "b", "b", "a", index: 0, input: "abba", groups: undefined]

const str2 = "abca";
const result2 = regex.exec(str2);
console.log(result2); // 输出: null
```

在这个例子中，`\2` 必须匹配第二个捕获组 `(.)` 实际匹配到的字符，`\1` 必须匹配第一个捕获组 `(.)` 实际匹配到的字符。

**归纳一下它的功能 (第2部分):**

这部分代码主要集中在测试 **V8 引擎中 `NativeRegExpMacroAssembler` 的各种指令和功能**。它通过构建不同的正则表达式匹配场景，例如回溯、反向引用（区分大小写和不区分大小写）、起始位置匹配、寄存器操作和栈溢出等，来验证 `NativeRegExpMacroAssembler` 的正确性和健壮性。此外，还包含了对 `RegExpBytecodeGenerator` 的基本测试。这些测试是 V8 引擎保证其正则表达式功能正确高效的重要组成部分。

Prompt: 
```
这是目录为v8/test/unittests/regexp/regexp-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/regexp/regexp-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
egExpTest, MacroAssemblerNativeBacktrack) {
  ContextInitializer initializer;
  Factory* factory = i_isolate()->factory();
  Zone zone(i_isolate()->allocator(), ZONE_NAME);

  ArchRegExpMacroAssembler m(i_isolate(), &zone,
                             NativeRegExpMacroAssembler::LATIN1, 0);

  Label fail;
  Label backtrack;
  m.LoadCurrentCharacter(10, &fail);
  m.Succeed();
  m.BindJumpTarget(&fail);
  m.PushBacktrack(&backtrack);
  m.LoadCurrentCharacter(10, nullptr);
  m.Succeed();
  m.BindJumpTarget(&backtrack);
  m.Fail();

  Handle<String> source = factory->NewStringFromStaticChars("..........");
  DirectHandle<Object> code_object = m.GetCode(source, {});
  DirectHandle<Code> code = Cast<Code>(code_object);
  DirectHandle<JSRegExp> regexp = CreateJSRegExp(source, code);

  DirectHandle<String> input = factory->NewStringFromStaticChars("foofoo");
  DirectHandle<SeqOneByteString> seq_input = Cast<SeqOneByteString>(input);
  Address start_adr = seq_input->GetCharsAddress();

  NativeRegExpMacroAssembler::Result result = Execute(
      *regexp, *input, 0, start_adr, start_adr + input->length(), nullptr);

  CHECK_EQ(NativeRegExpMacroAssembler::FAILURE, result);
}

TEST_F(RegExpTest, MacroAssemblerNativeBackReferenceLATIN1) {
  ContextInitializer initializer;
  Factory* factory = i_isolate()->factory();
  Zone zone(i_isolate()->allocator(), ZONE_NAME);

  ArchRegExpMacroAssembler m(i_isolate(), &zone,
                             NativeRegExpMacroAssembler::LATIN1, 4);

  m.WriteCurrentPositionToRegister(0, 0);
  m.AdvanceCurrentPosition(2);
  m.WriteCurrentPositionToRegister(1, 0);
  Label nomatch;
  m.CheckNotBackReference(0, false, &nomatch);
  m.Fail();
  m.Bind(&nomatch);
  m.AdvanceCurrentPosition(2);
  Label missing_match;
  m.CheckNotBackReference(0, false, &missing_match);
  m.WriteCurrentPositionToRegister(2, 0);
  m.Succeed();
  m.Bind(&missing_match);
  m.Fail();

  Handle<String> source = factory->NewStringFromStaticChars("^(..)..\1");
  DirectHandle<Object> code_object = m.GetCode(source, {});
  DirectHandle<Code> code = Cast<Code>(code_object);
  DirectHandle<JSRegExp> regexp = CreateJSRegExp(source, code);

  DirectHandle<String> input = factory->NewStringFromStaticChars("fooofo");
  DirectHandle<SeqOneByteString> seq_input = Cast<SeqOneByteString>(input);
  Address start_adr = seq_input->GetCharsAddress();

  int output[4];
  NativeRegExpMacroAssembler::Result result = Execute(
      *regexp, *input, 0, start_adr, start_adr + input->length(), output);

  CHECK_EQ(NativeRegExpMacroAssembler::SUCCESS, result);
  CHECK_EQ(0, output[0]);
  CHECK_EQ(2, output[1]);
  CHECK_EQ(6, output[2]);
  CHECK_EQ(-1, output[3]);
}

TEST_F(RegExpTest, MacroAssemblerNativeBackReferenceUC16) {
  ContextInitializer initializer;
  Factory* factory = i_isolate()->factory();
  Zone zone(i_isolate()->allocator(), ZONE_NAME);

  ArchRegExpMacroAssembler m(i_isolate(), &zone,
                             NativeRegExpMacroAssembler::UC16, 4);

  m.WriteCurrentPositionToRegister(0, 0);
  m.AdvanceCurrentPosition(2);
  m.WriteCurrentPositionToRegister(1, 0);
  Label nomatch;
  m.CheckNotBackReference(0, false, &nomatch);
  m.Fail();
  m.Bind(&nomatch);
  m.AdvanceCurrentPosition(2);
  Label missing_match;
  m.CheckNotBackReference(0, false, &missing_match);
  m.WriteCurrentPositionToRegister(2, 0);
  m.Succeed();
  m.Bind(&missing_match);
  m.Fail();

  Handle<String> source = factory->NewStringFromStaticChars("^(..)..\1");
  DirectHandle<Object> code_object = m.GetCode(source, {});
  DirectHandle<Code> code = Cast<Code>(code_object);
  DirectHandle<JSRegExp> regexp = CreateJSRegExp(source, code, true);

  const base::uc16 input_data[6] = {'f', 0x2028, 'o', 'o', 'f', 0x2028};
  DirectHandle<String> input =
      factory
          ->NewStringFromTwoByte(base::Vector<const base::uc16>(input_data, 6))
          .ToHandleChecked();
  DirectHandle<SeqTwoByteString> seq_input = Cast<SeqTwoByteString>(input);
  Address start_adr = seq_input->GetCharsAddress();

  int output[4];
  NativeRegExpMacroAssembler::Result result = Execute(
      *regexp, *input, 0, start_adr, start_adr + input->length() * 2, output);

  CHECK_EQ(NativeRegExpMacroAssembler::SUCCESS, result);
  CHECK_EQ(0, output[0]);
  CHECK_EQ(2, output[1]);
  CHECK_EQ(6, output[2]);
  CHECK_EQ(-1, output[3]);
}

TEST_F(RegExpTest, MacroAssemblernativeAtStart) {
  ContextInitializer initializer;
  Factory* factory = i_isolate()->factory();
  Zone zone(i_isolate()->allocator(), ZONE_NAME);

  ArchRegExpMacroAssembler m(i_isolate(), &zone,
                             NativeRegExpMacroAssembler::LATIN1, 0);

  Label not_at_start, newline, fail;
  m.CheckNotAtStart(0, &not_at_start);
  // Check that prevchar = '\n' and current = 'f'.
  m.CheckCharacter('\n', &newline);
  m.BindJumpTarget(&fail);
  m.Fail();
  m.Bind(&newline);
  m.LoadCurrentCharacter(0, &fail);
  m.CheckNotCharacter('f', &fail);
  m.Succeed();

  m.Bind(&not_at_start);
  // Check that prevchar = 'o' and current = 'b'.
  Label prevo;
  m.CheckCharacter('o', &prevo);
  m.Fail();
  m.Bind(&prevo);
  m.LoadCurrentCharacter(0, &fail);
  m.CheckNotCharacter('b', &fail);
  m.Succeed();

  Handle<String> source = factory->NewStringFromStaticChars("(^f|ob)");
  DirectHandle<Object> code_object = m.GetCode(source, {});
  DirectHandle<Code> code = Cast<Code>(code_object);
  DirectHandle<JSRegExp> regexp = CreateJSRegExp(source, code);

  DirectHandle<String> input = factory->NewStringFromStaticChars("foobar");
  DirectHandle<SeqOneByteString> seq_input = Cast<SeqOneByteString>(input);
  Address start_adr = seq_input->GetCharsAddress();

  NativeRegExpMacroAssembler::Result result = Execute(
      *regexp, *input, 0, start_adr, start_adr + input->length(), nullptr);

  CHECK_EQ(NativeRegExpMacroAssembler::SUCCESS, result);

  result = Execute(*regexp, *input, 3, start_adr + 3,
                   start_adr + input->length(), nullptr);

  CHECK_EQ(NativeRegExpMacroAssembler::SUCCESS, result);
}

TEST_F(RegExpTest, MacroAssemblerNativeBackRefNoCase) {
  ContextInitializer initializer;
  Factory* factory = i_isolate()->factory();
  Zone zone(i_isolate()->allocator(), ZONE_NAME);

  ArchRegExpMacroAssembler m(i_isolate(), &zone,
                             NativeRegExpMacroAssembler::LATIN1, 4);

  Label fail, succ;

  m.WriteCurrentPositionToRegister(0, 0);
  m.WriteCurrentPositionToRegister(2, 0);
  m.AdvanceCurrentPosition(3);
  m.WriteCurrentPositionToRegister(3, 0);
  m.CheckNotBackReferenceIgnoreCase(2, false, false, &fail);  // Match "AbC".
  m.CheckNotBackReferenceIgnoreCase(2, false, false, &fail);  // Match "ABC".
  Label expected_fail;
  m.CheckNotBackReferenceIgnoreCase(2, false, false, &expected_fail);
  m.BindJumpTarget(&fail);
  m.Fail();

  m.Bind(&expected_fail);
  m.AdvanceCurrentPosition(3);  // Skip "xYz"
  m.CheckNotBackReferenceIgnoreCase(2, false, false, &succ);
  m.Fail();

  m.Bind(&succ);
  m.WriteCurrentPositionToRegister(1, 0);
  m.Succeed();

  Handle<String> source =
      factory->NewStringFromStaticChars("^(abc)\1\1(?!\1)...(?!\1)");
  DirectHandle<Object> code_object = m.GetCode(source, {});
  DirectHandle<Code> code = Cast<Code>(code_object);
  DirectHandle<JSRegExp> regexp = CreateJSRegExp(source, code);

  DirectHandle<String> input =
      factory->NewStringFromStaticChars("aBcAbCABCxYzab");
  DirectHandle<SeqOneByteString> seq_input = Cast<SeqOneByteString>(input);
  Address start_adr = seq_input->GetCharsAddress();

  int output[4];
  NativeRegExpMacroAssembler::Result result = Execute(
      *regexp, *input, 0, start_adr, start_adr + input->length(), output);

  CHECK_EQ(NativeRegExpMacroAssembler::SUCCESS, result);
  CHECK_EQ(0, output[0]);
  CHECK_EQ(12, output[1]);
  CHECK_EQ(0, output[2]);
  CHECK_EQ(3, output[3]);
}

TEST_F(RegExpTest, MacroAssemblerNativeRegisters) {
  ContextInitializer initializer;
  Factory* factory = i_isolate()->factory();
  Zone zone(i_isolate()->allocator(), ZONE_NAME);

  ArchRegExpMacroAssembler m(i_isolate(), &zone,
                             NativeRegExpMacroAssembler::LATIN1, 6);

  base::uc16 foo_chars[3] = {'f', 'o', 'o'};
  base::Vector<const base::uc16> foo(foo_chars, 3);

  enum registers { out1, out2, out3, out4, out5, out6, sp, loop_cnt };
  Label fail;
  Label backtrack;
  m.WriteCurrentPositionToRegister(out1, 0);  // Output: [0]
  m.PushRegister(out1, RegExpMacroAssembler::kNoStackLimitCheck);
  m.PushBacktrack(&backtrack);
  m.WriteStackPointerToRegister(sp);
  // Fill stack and registers
  m.AdvanceCurrentPosition(2);
  m.WriteCurrentPositionToRegister(out1, 0);
  m.PushRegister(out1, RegExpMacroAssembler::kNoStackLimitCheck);
  m.PushBacktrack(&fail);
  // Drop backtrack stack frames.
  m.ReadStackPointerFromRegister(sp);
  // And take the first backtrack (to &backtrack)
  m.Backtrack();

  m.PushCurrentPosition();
  m.AdvanceCurrentPosition(2);
  m.PopCurrentPosition();

  m.BindJumpTarget(&backtrack);
  m.PopRegister(out1);
  m.ReadCurrentPositionFromRegister(out1);
  m.AdvanceCurrentPosition(3);
  m.WriteCurrentPositionToRegister(out2, 0);  // [0,3]

  Label loop;
  m.SetRegister(loop_cnt, 0);  // loop counter
  m.Bind(&loop);
  m.AdvanceRegister(loop_cnt, 1);
  m.AdvanceCurrentPosition(1);
  m.IfRegisterLT(loop_cnt, 3, &loop);
  m.WriteCurrentPositionToRegister(out3, 0);  // [0,3,6]

  Label loop2;
  m.SetRegister(loop_cnt, 2);  // loop counter
  m.Bind(&loop2);
  m.AdvanceRegister(loop_cnt, -1);
  m.AdvanceCurrentPosition(1);
  m.IfRegisterGE(loop_cnt, 0, &loop2);
  m.WriteCurrentPositionToRegister(out4, 0);  // [0,3,6,9]

  Label loop3;
  Label exit_loop3;
  m.PushRegister(out4, RegExpMacroAssembler::kNoStackLimitCheck);
  m.PushRegister(out4, RegExpMacroAssembler::kNoStackLimitCheck);
  m.ReadCurrentPositionFromRegister(out3);
  m.Bind(&loop3);
  m.AdvanceCurrentPosition(1);
  m.CheckGreedyLoop(&exit_loop3);
  m.GoTo(&loop3);
  m.Bind(&exit_loop3);
  m.PopCurrentPosition();
  m.WriteCurrentPositionToRegister(out5, 0);  // [0,3,6,9,9,-1]

  m.Succeed();

  m.BindJumpTarget(&fail);
  m.Fail();

  Handle<String> source = factory->NewStringFromStaticChars("<loop test>");
  DirectHandle<Object> code_object = m.GetCode(source, {});
  DirectHandle<Code> code = Cast<Code>(code_object);
  DirectHandle<JSRegExp> regexp = CreateJSRegExp(source, code);

  // String long enough for test (content doesn't matter).
  DirectHandle<String> input =
      factory->NewStringFromStaticChars("foofoofoofoofoo");
  DirectHandle<SeqOneByteString> seq_input = Cast<SeqOneByteString>(input);
  Address start_adr = seq_input->GetCharsAddress();

  int output[6];
  NativeRegExpMacroAssembler::Result result = Execute(
      *regexp, *input, 0, start_adr, start_adr + input->length(), output);

  CHECK_EQ(NativeRegExpMacroAssembler::SUCCESS, result);
  CHECK_EQ(0, output[0]);
  CHECK_EQ(3, output[1]);
  CHECK_EQ(6, output[2]);
  CHECK_EQ(9, output[3]);
  CHECK_EQ(9, output[4]);
  CHECK_EQ(-1, output[5]);
}

TEST_F(RegExpTest, MacroAssemblerStackOverflow) {
  ContextInitializer initializer;
  Factory* factory = i_isolate()->factory();
  Zone zone(i_isolate()->allocator(), ZONE_NAME);

  ArchRegExpMacroAssembler m(i_isolate(), &zone,
                             NativeRegExpMacroAssembler::LATIN1, 0);

  Label loop;
  m.Bind(&loop);
  m.PushBacktrack(&loop);
  m.GoTo(&loop);

  Handle<String> source =
      factory->NewStringFromStaticChars("<stack overflow test>");
  DirectHandle<Object> code_object = m.GetCode(source, {});
  DirectHandle<Code> code = Cast<Code>(code_object);
  DirectHandle<JSRegExp> regexp = CreateJSRegExp(source, code);

  // String long enough for test (content doesn't matter).
  DirectHandle<String> input = factory->NewStringFromStaticChars("dummy");
  DirectHandle<SeqOneByteString> seq_input = Cast<SeqOneByteString>(input);
  Address start_adr = seq_input->GetCharsAddress();

  NativeRegExpMacroAssembler::Result result = Execute(
      *regexp, *input, 0, start_adr, start_adr + input->length(), nullptr);

  CHECK_EQ(NativeRegExpMacroAssembler::EXCEPTION, result);
  CHECK(isolate()->has_exception());
  isolate()->clear_exception();
}

TEST_F(RegExpTest, MacroAssemblerNativeLotsOfRegisters) {
  ContextInitializer initializer;
  Factory* factory = i_isolate()->factory();
  Zone zone(i_isolate()->allocator(), ZONE_NAME);

  ArchRegExpMacroAssembler m(i_isolate(), &zone,
                             NativeRegExpMacroAssembler::LATIN1, 2);

  // At least 2048, to ensure the allocated space for registers
  // span one full page.
  const int large_number = 8000;
  m.WriteCurrentPositionToRegister(large_number, 42);
  m.WriteCurrentPositionToRegister(0, 0);
  m.WriteCurrentPositionToRegister(1, 1);
  Label done;
  m.CheckNotBackReference(0, false, &done);  // Performs a system-stack push.
  m.Bind(&done);
  m.PushRegister(large_number, RegExpMacroAssembler::kNoStackLimitCheck);
  m.PopRegister(1);
  m.Succeed();

  Handle<String> source =
      factory->NewStringFromStaticChars("<huge register space test>");
  DirectHandle<Object> code_object = m.GetCode(source, {});
  DirectHandle<Code> code = Cast<Code>(code_object);
  DirectHandle<JSRegExp> regexp = CreateJSRegExp(source, code);

  // String long enough for test (content doesn't matter).
  DirectHandle<String> input = factory->NewStringFromStaticChars("sample text");
  DirectHandle<SeqOneByteString> seq_input = Cast<SeqOneByteString>(input);
  Address start_adr = seq_input->GetCharsAddress();

  int captures[2];
  NativeRegExpMacroAssembler::Result result = Execute(
      *regexp, *input, 0, start_adr, start_adr + input->length(), captures);

  CHECK_EQ(NativeRegExpMacroAssembler::SUCCESS, result);
  CHECK_EQ(0, captures[0]);
  CHECK_EQ(42, captures[1]);

  isolate()->clear_exception();
}

TEST_F(RegExpTest, MacroAssembler) {
  Zone zone(i_isolate()->allocator(), ZONE_NAME);
  RegExpBytecodeGenerator m(i_isolate(), &zone);
  // ^f(o)o.
  Label start, fail, backtrack;

  m.SetRegister(4, 42);
  m.PushRegister(4, RegExpMacroAssembler::kNoStackLimitCheck);
  m.AdvanceRegister(4, 42);
  m.GoTo(&start);
  m.Fail();
  m.Bind(&start);
  m.PushBacktrack(&fail);
  m.CheckNotAtStart(0, nullptr);
  m.LoadCurrentCharacter(0, nullptr);
  m.CheckNotCharacter('f', nullptr);
  m.LoadCurrentCharacter(1, nullptr);
  m.CheckNotCharacter('o', nullptr);
  m.LoadCurrentCharacter(2, nullptr);
  m.CheckNotCharacter('o', nullptr);
  m.WriteCurrentPositionToRegister(0, 0);
  m.WriteCurrentPositionToRegister(1, 3);
  m.WriteCurrentPositionToRegister(2, 1);
  m.WriteCurrentPositionToRegister(3, 2);
  m.AdvanceCurrentPosition(3);
  m.PushBacktrack(&backtrack);
  m.Succeed();
  m.BindJumpTarget(&backtrack);
  m.ClearRegisters(2, 3);
  m.Backtrack();
  m.BindJumpTarget(&fail);
  m.PopRegister(0);
  m.Fail();

  Factory* factory = i_isolate()->factory();
  HandleScope scope(i_isolate());

  Handle<String> source = factory->NewStringFromStaticChars("^f(o)o");
  DirectHandle<TrustedByteArray> array =
      Cast<TrustedByteArray>(m.GetCode(source, {}));
  int captures[5];
  std::memset(captures, 0, sizeof(captures));

  const base::uc16 str1[] = {'f', 'o', 'o', 'b', 'a', 'r'};
  DirectHandle<String> f1_16 =
      factory->NewStringFromTwoByte(base::Vector<const base::uc16>(str1, 6))
          .ToHandleChecked();

  {
    Tagged<TrustedByteArray> array_unhandlified = *array;
    Tagged<String> subject_unhandlified = *f1_16;
    CHECK_EQ(IrregexpInterpreter::SUCCESS,
             IrregexpInterpreter::MatchInternal(
                 isolate(), &array_unhandlified, &subject_unhandlified,
                 captures, 5, 5, 0, RegExp::CallOrigin::kFromRuntime,
                 JSRegExp::kNoBacktrackLimit));
    CHECK_EQ(0, captures[0]);
    CHECK_EQ(3, captures[1]);
    CHECK_EQ(1, captures[2]);
    CHECK_EQ(2, captures[3]);
    CHECK_EQ(84, captures[4]);
  }

  const base::uc16 str2[] = {'b', 'a', 'r', 'f', 'o', 'o'};
  DirectHandle<String> f2_16 =
      factory->NewStringFromTwoByte(base::Vector<const base::uc16>(str2, 6))
          .ToHandleChecked();

  {
    Tagged<TrustedByteArray> array_unhandlified = *array;
    Tagged<String> subject_unhandlified = *f2_16;
    std::memset(captures, 0, sizeof(captures));
    CHECK_EQ(IrregexpInterpreter::FAILURE,
             IrregexpInterpreter::MatchInternal(
                 isolate(), &array_unhandlified, &subject_unhandlified,
                 captures, 5, 5, 0, RegExp::CallOrigin::kFromRuntime,
                 JSRegExp::kNoBacktrackLimit));
    // Failed matches don't alter output registers.
    CHECK_EQ(0, captures[0]);
    CHECK_EQ(0, captures[1]);
    CHECK_EQ(0, captures[2]);
    CHECK_EQ(0, captures[3]);
    CHECK_EQ(0, captures[4]);
  }
}

#ifndef V8_INTL_SUPPORT
static base::uc32 canonicalize(base::uc32 c) {
  unibrow::uchar canon[unibrow::Ecma262Canonicalize::kMaxWidth];
  int count = unibrow::Ecma262Canonicalize::Convert(c, '\0', canon, nullptr);
  if (count == 0) {
    return c;
  } else {
    CHECK_EQ(1, count);
    return canon[0];
  }
}

TEST_F(RegExpTest, LatinCanonicalize) {
  unibrow::Mapping<unibrow::Ecma262UnCanonicalize> un_canonicalize;
  for (unibrow::uchar lower = 'a'; lower <= 'z'; lower++) {
    unibrow::uchar upper = lower + ('A' - 'a');
    CHECK_EQ(canonicalize(lower), canonicalize(upper));
    unibrow::uchar uncanon[unibrow::Ecma262UnCanonicalize::kMaxWidth];
    int length = un_canonicalize.get(lower, '\0', uncanon);
    CHECK_EQ(2, length);
    CHECK_EQ(upper, uncanon[0]);
    CHECK_EQ(lower, uncanon[1]);
  }
  for (base::uc32 c = 128; c < (1 << 21); c++) CHECK_GE(canonicalize(c), 128);
  unibrow::Mapping<unibrow::ToUppercase> to_upper;
  // Canonicalization is only defined for the Basic Multilingual Plane.
  for (base::uc32 c = 0; c < (1 << 16); c++) {
    unibrow::uchar upper[unibrow::ToUppercase::kMaxWidth];
    int length = to_upper.get(c, '\0', upper);
    if (length == 0) {
      length = 1;
      upper[0] = c;
    }
    base::uc32 u = upper[0];
    if (length > 1 || (c >= 128 && u < 128)) u = c;
    CHECK_EQ(u, canonicalize(c));
  }
}

static base::uc32 CanonRangeEnd(base::uc32 c) {
  unibrow::uchar canon[unibrow::CanonicalizationRange::kMaxWidth];
  int count = unibrow::CanonicalizationRange::Convert(c, '\0', canon, nullptr);
  if (count == 0) {
    return c;
  } else {
    CHECK_EQ(1, count);
    return canon[0];
  }
}

TEST_F(RegExpTest, RangeCanonicalization) {
  // Check that we arrive at the same result when using the basic
  // range canonicalization primitives as when using immediate
  // canonicalization.
  unibrow::Mapping<unibrow::Ecma262UnCanonicalize> un_canonicalize;
  int block_start = 0;
  while (block_start <= 0xFFFF) {
    base::uc32 block_end = CanonRangeEnd(block_start);
    unsigned block_length = block_end - block_start + 1;
    if (block_length > 1) {
      unibrow::uchar first[unibrow::Ecma262UnCanonicalize::kMaxWidth];
      int first_length = un_canonicalize.get(block_start, '\0', first);
      for (unsigned i = 1; i < block_length; i++) {
        unibrow::uchar succ[unibrow::Ecma262UnCanonicalize::kMaxWidth];
        int succ_length = un_canonicalize.get(block_start + i, '\0', succ);
        CHECK_EQ(first_length, succ_length);
        for (int j = 0; j < succ_length; j++) {
          int calc = first[j] + i;
          int found = succ[j];
          CHECK_EQ(calc, found);
        }
      }
    }
    block_start = block_start + block_length;
  }
}

TEST_F(RegExpTest, UncanonicalizeEquivalence) {
  unibrow::Mapping<unibrow::Ecma262UnCanonicalize> un_canonicalize;
  unibrow::uchar chars[unibrow::Ecma262UnCanonicalize::kMaxWidth];
  for (int i = 0; i < (1 << 16); i++) {
    int length = un_canonicalize.get(i, '\0', chars);
    for (int j = 0; j < length; j++) {
      unibrow::uchar chars2[unibrow::Ecma262UnCanonicalize::kMaxWidth];
      int length2 = un_canonicalize.get(chars[j], '\0', chars2);
      CHECK_EQ(length, length2);
      for (int k = 0; k < length; k++)
        CHECK_EQ(static_cast<int>(chars[k]), static_cast<int>(chars2[k]));
    }
  }
}

#endif

static void TestRangeCaseIndependence(Isolate* isolate, CharacterRange input,
                                      base::Vector<CharacterRange> expected) {
  Zone zone(
      reinterpret_cast<i::Isolate*>(v8::Isolate::GetCurrent())->allocator(),
      ZONE_NAME);
  int count = expected.length();
  ZoneList<CharacterRange>* list =
      zone.New<ZoneList<CharacterRange>>(count, &zone);
  list->Add(input, &zone);
  CharacterRange::AddCaseEquivalents(isolate, &zone, list, false);
  list->Remove(0);  // Remove the input before checking results.
  CHECK_EQ(count, list->length());
  for (int i = 0; i < list->length(); i++) {
    CHECK_EQ(expected[i].from(), list->at(i).from());
    CHECK_EQ(expected[i].to(), list->at(i).to());
  }
}

static void TestSimpleRangeCaseIndependence(Isolate* isolate,
                                            CharacterRange input,
                                            CharacterRange expected) {
  base::EmbeddedVector<CharacterRange, 1> vector;
  vector[0] = expected;
  TestRangeCaseIndependence(isolate, input, vector);
}

TEST_F(RegExpTest, CharacterRangeCaseIndependence) {
  TestSimpleRangeCaseIndependence(i_isolate(), CharacterRange::Singleton('a'),
                                  CharacterRange::Singleton('A'));
  TestSimpleRangeCaseIndependence(i_isolate(), CharacterRange::Singleton('z'),
                                  CharacterRange::Singleton('Z'));
#ifndef V8_INTL_SUPPORT
  TestSimpleRangeCaseIndependence(i_isolate(), CharacterRange::Range('a', 'z'),
                                  CharacterRange::Range('A', 'Z'));
#endif  // !V8_INTL_SUPPORT
  TestSimpleRangeCaseIndependence(i_isolate(), CharacterRange::Range('c', 'f'),
                                  CharacterRange::Range('C', 'F'));
  TestSimpleRangeCaseIndependence(i_isolate(), CharacterRange::Range('a', 'b'),
                                  CharacterRange::Range('A', 'B'));
  TestSimpleRangeCaseIndependence(i_isolate(), CharacterRange::Range('y', 'z'),
                                  CharacterRange::Range('Y', 'Z'));
#ifndef V8_INTL_SUPPORT
  TestSimpleRangeCaseIndependence(i_isolate(),
                                  CharacterRange::Range('a' - 1, 'z' + 1),
                                  CharacterRange::Range('A', 'Z'));
  TestSimpleRangeCaseIndependence(i_isolate(), CharacterRange::Range('A', 'Z'),
                                  CharacterRange::Range('a', 'z'));
#endif  // !V8_INTL_SUPPORT
  TestSimpleRangeCaseIndependence(i_isolate(), CharacterRange::Range('C', 'F'),
                                  CharacterRange::Range('c', 'f'));
#ifndef V8_INTL_SUPPORT
  TestSimpleRangeCaseIndependence(i_isolate(),
                                  CharacterRange::Range('A' - 1, 'Z' + 1),
                                  CharacterRange::Range('a', 'z'));
  // Here we need to add [l-z] to complete the case independence of
  // [A-Za-z] but we expect [a-z] to be added since we always add a
  // whole block at a time.
  TestSimpleRangeCaseIndependence(i_isolate(), CharacterRange::Range('A', 'k'),
                                  CharacterRange::Range('a', 'z'));
#endif  // !V8_INTL_SUPPORT
}

static bool InClass(base::uc32 c,
                    const UnicodeRangeSplitter::CharacterRangeVector* ranges) {
  if (ranges == nullptr) return false;
  for (size_t i = 0; i < ranges->size(); i++) {
    CharacterRange range = ranges->at(i);
    if (range.from() <= c && c <= range.to()) return true;
  }
  return false;
}

TEST_F(RegExpTest, UnicodeRangeSplitter) {
  Zone zone(i_isolate()->allocator(), ZONE_NAME);
  ZoneList<CharacterRange>* base = zone.New<ZoneList<CharacterRange>>(1, &zone);
  base->Add(CharacterRange::Everything(), &zone);
  UnicodeRangeSplitter splitter(base);
  // BMP
  for (base::uc32 c = 0; c < 0xD800; c++) {
    CHECK(InClass(c, splitter.bmp()));
    CHECK(!InClass(c, splitter.lead_surrogates()));
    CHECK(!InClass(c, splitter.trail_surrogates()));
    CHECK(!InClass(c, splitter.non_bmp()));
  }
  // Lead surrogates
  for (base::uc32 c = 0xD800; c < 0xDBFF; c++) {
    CHECK(!InClass(c, splitter.bmp()));
    CHECK(InClass(c, splitter.lead_surrogates()));
    CHECK(!InClass(c, splitter.trail_surrogates()));
    CHECK(!InClass(c, splitter.non_bmp()));
  }
  // Trail surrogates
  for (base::uc32 c = 0xDC00; c < 0xDFFF; c++) {
    CHECK(!InClass(c, splitter.bmp()));
    CHECK(!InClass(c, splitter.lead_surrogates()));
    CHECK(InClass(c, splitter.trail_surrogates()));
    CHECK(!InClass(c, splitter.non_bmp()));
  }
  // BMP
  for (base::uc32 c = 0xE000; c < 0xFFFF; c++) {
    CHECK(InClass(c, splitter.bmp()));
    CHECK(!InClass(c, splitter.lead_surrogates()));
    CHECK(!InClass(c, splitter.trail_surrogates()));
    CHECK(!InClass(c, splitter.non_bmp()));
  }
  // Non-BMP
  for (base::uc32 c = 0x10000; c < 0x10FFFF; c++) {
    CHECK(!InClass(c, splitter.bmp()));
    CHECK(!InClass(c, splitter.lead_surrogates()));
    CHECK(!InClass(c, splitter.trail_surrogates()));
    CHECK(InClass(c, splitter.non_bmp()));
  }
}

TEST_F(RegExpTest, CanonicalizeCharacterSets) {
  Zone zone(i_isolate()->allocator(), ZONE_NAME);
  ZoneList<CharacterRange>* list = zone.New<ZoneList<CharacterRange>>(4, &zone);
  CharacterSet set(list);

  list->Add(CharacterRange::Range(10, 20), &zone);
  list->Add(CharacterRange::Range(30, 40), &zone);
  list->Add(CharacterRange::Range(50, 60), &zone);
  set.Canonicalize();
  CHECK_EQ(3, list->length());
  CHECK_EQ(10, list->at(0).from());
  CHECK_EQ(20, list->at(0).to());
  CHECK_EQ(30, list->at(1).from());
  CHECK_EQ(40, list->at(1).to());
  CHECK_EQ(50, list->at(2).from());
  CHECK_EQ(60, list->at(2).to());

  list->Rewind(0);
  list->Add(CharacterRange::Range(10, 20), &zone);
  list->Add(CharacterRange::Range(50, 60), &zone);
  list->Add(CharacterRange::Range(30, 40), &zone);
  set.Canonicalize();
  CHECK_EQ(3, list->length());
  CHECK_EQ(10, list->at(0).from());
  CHECK_EQ(20, list->at(0).to());
  CHECK_EQ(30, list->at(1).from());
  CHECK_EQ(40, list->at(1).to());
  CHECK_EQ(50, list->at(2).from());
  CHECK_EQ(60, list->at(2).to());

  list->Rewind(0);
  list->Add(CharacterRange::Range(30, 40), &zone);
  list->Add(CharacterRange::Range(10, 20), &zone);
  list->Add(CharacterRange::Range(25, 25), &zone);
  list->Add(CharacterRange::Range(100, 100), &zone);
  list->Add(CharacterRange::Range(1, 1), &zone);
  set.Canonicalize();
  CHECK_EQ(5, list->length());
  CHECK_EQ(1, list->at(0).from());
  CHECK_EQ(1, list->at(0).to());
  CHECK_EQ(10, list->at(1).from());
  CHECK_EQ(20, list->at(1).to());
  CHECK_EQ(25, list->at(2).from());
  CHECK_EQ(25, list->at(2).to());
  CHECK_EQ(30, list->at(3).from());
  CHECK_EQ(40, list->at(3).to());
  CHECK_EQ(100, list->at(4).from());
  CHECK_EQ(100, list->at(4).to());

  list->Rewind(0);
  list->Add(CharacterRange::Range(10, 19), &zone);
  list->Add(CharacterRange::Range(21, 30), &zone);
  list->Add(CharacterRange::Range(20, 20), &zone);
  set.Canonicalize();
  CHECK_EQ(1, list->length());
  CHECK_EQ(10, list->at(0).from());
  CHECK_EQ(30, list->at(0).to());
}

TEST_F(RegExpTest, CharacterRangeMerge) {
  Zone zone(i_isolate()->allocator(), ZONE_NAME);
  ZoneList<CharacterRange> l1(4, &zone);
  ZoneList<CharacterRange> l2(4, &zone);
  // Create all combinations of intersections of ranges, both singletons and
  // longer.

  int offset = 0;

  // The five kinds of singleton intersections:
  //     X
  //   Y      - outside before
  //    Y     - outside touching start
  //     Y    - overlap
  //      Y   - outside touching end
  //       Y  - outside after

  for (int i = 0; i < 5; i++) {
    l1.Add(CharacterRange::Singleton(offset + 2), &zone);
    l2.Add(CharacterRange::Singleton(offset + i), &zone);
    offset += 6;
  }

  // The seven kinds of singleton/non-singleton intersections:
  //    XXX
  //  Y        - outside before
  //   Y       - outside touching start
  //    Y      - inside touching start
  //     Y     - entirely inside
  //      Y    - inside touching end
  //       Y   - outside touching end
  //        Y  - disjoint after

  for (int i = 0; i < 7; i++) {
    l1.Add(CharacterRange::Range(offset + 2, offset + 4), &zone);
    l2.Add(CharacterRange::Singleton(offset + i), &zone);
    offset += 8;
  }

  // The eleven kinds of non-singleton intersections:
  //
  //       XXXXXXXX
  // YYYY                  - outside before.
  //   YYYY                - outside touching start.
  //     YYYY              - overlapping start
  //       YYYY            - inside touching start
  //         YYYY          - entirely inside
  //           YYYY        - inside touching end
  //             YYYY      - overlapping end
  //               YYYY    - outside touching end
  //                 YYYY  - outside after
  //       YYYYYYYY        - identical
  //     YYYYYYYYYYYY      - containing entirely.

  for (int i = 0; i < 9; i++) {
    l1.Add(CharacterRange::Range(offset + 6, offset + 15), &zone);  // Length 8.
    l2.Add(CharacterRange::Range(offset + 2 * i, offset + 2 * i + 3), &zone);
    offset += 22;
  }
  l1.Add(CharacterRange::Range(offset + 6, offset + 15), &zone);
  l2.Add(CharacterRange::Range(offset + 6, offset + 15), &zone);
  offset += 22;
  l1.Add(CharacterRange::Range(offset + 6, offset + 15), &zone);
  l2.Add(CharacterRange::Range(offset + 4, offset + 17), &zone);
  offset += 22;

  // Different kinds of multi-range overlap:
  // XXXXXXXXXXXXXXXXXXXXXX         XXXXXXXXXXXXXXXXXXXXXX
  //   YYYY  Y  YYYY  Y  YYYY  Y  YYYY  Y  YYYY  Y  YYYY  Y

  l1.Add(CharacterRange::Range(offset, offset + 21), &zone);
  l1.Add(CharacterRange::Range(offset + 31, offset + 52), &zone);
  for (int i = 0; i < 6; i++) {
    l2.Add(CharacterRange::Range(offset + 2, offset + 5), &zone);
    l2.Add(CharacterRange::Singleton(offset + 8), &zone);
    offset += 9;
  }

  CHECK(CharacterRange::IsCanonical(&l1));
  CHECK(CharacterRange::IsCanonical(&l2));

  ZoneList<CharacterRange> first_only(4, &zone);
  ZoneList<CharacterRange> second_only(4, &zone);
  ZoneList<CharacterRange> both(4, &zone);
}

TEST_F(RegExpTest, Graph) { Execute("\\b\\w+\\b", false, true, true); }

namespace {

int* global_use_counts = nullptr;

void MockUseCounterCallback(v8::Isolate* isolate,
                            v8::Isolate::UseCounterFeature feature) {
  ++global_use_counts[feature];
}

}  // namespace

using RegExpTestWithContext = TestWithContext;
// Test that ES2015+ RegExp compatibility fixes are in place, that they
// are not overly broad, and the appropriate UseCounters are incremented
TEST_F(RegExpTestWithContext, UseCountRegExp) {
  v8::HandleScope scope(isolate());
  int use_counts[v8::Isolate::kUseCounterFeatureCount] = {};
  global_use_counts = use_counts;
  isolate()->SetUseCounterCallback(MockUseCounterCallback);

  // Compat fix: RegExp.prototype.sticky == undefined; UseCounter tracks it
  v8::Local<v8::Value> resultSticky = RunJS("RegExp.prototype.sticky");
  CHECK_EQ(1, use_counts[v8::Isolate::kRegExpPrototypeStickyGetter]);
  CHECK_EQ(0, use_counts[v8::Isolate::kRegExpPrototypeToString]);
  CHECK(resultSticky->IsUndefined());

  // re.sticky has approriate value and doesn't touch UseCounter
  v8::Local<v8::Value> resultReSticky = RunJS("/a/.sticky");
  CHECK_EQ(1, use_counts[v8::Isolate::kRegExpPrototypeStickyGetter]);
  CHECK_EQ(0, use_counts[v8::Isolate::kRegExpPrototypeToString]);
  CHECK(resultReSticky->IsFalse());

  // When the getter is called on another object, throw an exception
  // and don't increment the UseCounter
  v8::Local<v8::Value> resultStickyError = RunJS(
      "var exception;"
      "try { "
      "  Object.getOwnPropertyDescriptor(RegExp.prototype, 'sticky')"
      "      .get.call(null);"
      "} catch (e) {"
      "  exception = e;"
      "}"
      "exception");
  CHECK_EQ(1, use_counts[v8::Isolate::kRegExpPrototypeStickyGetter]);
  CHECK_EQ(0, use_counts[v8::Isolate::kRegExpPrototypeToString]);
  CHECK(resultStickyError->IsObject());

  // RegExp.prototype.toString() returns '/(?:)/' as a compatibility fix;
  // a UseCounter is incremented to track it.
  v8::Local<v8::Value> resultToString =
      RunJS("RegExp.prototype.toString().length");
  CHECK_EQ(2, use_counts[v8::Isolate::kRegExpPrototypeStickyGetter]);
  CHECK_EQ(1, use_counts[v8::Isolate::kRegExpPrototypeToString]);
  CHECK(resultToString->IsInt32());
  CHECK_EQ(
      6, resultToString->Int32Value(isolate()->GetCurrentContext()).FromJust());

  // .toString() works on normal RegExps
  v8::Local<v8::Value> resultReToString = RunJS("/a/.toString().length");
  CHECK_EQ(2, use_counts[v8::Isolate::kRegExpPrototypeStickyGetter]);
  CHECK_EQ(1, use_counts[v8::Isolate::kRegExpPrototypeToString]);
  CHECK(resultReToString->IsInt32());
  CHECK_EQ(
      3,
      resultReT
"""


```