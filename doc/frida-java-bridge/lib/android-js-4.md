Response:
### 功能归纳

该文件是 `frida-java-bridge` 的一部分，主要用于在 Android 平台上进行动态插桩（Dynamic Instrumentation），特别是针对 ART（Android Runtime）的底层操作。以下是其主要功能的归纳：

1. **指令重定位与重编译**：
   - 该文件实现了对 ARM 和 ARM64 架构的指令重定位和重编译功能。通过 `Arm64Relocator` 和 `Arm64Writer` 等工具，能够解析、修改和生成新的机器指令。
   - 例如，`recompileExceptionClearForArm64` 函数用于重新编译 `ExceptionClear` 方法的实现，以便在特定条件下插入自定义的回调函数。

2. **异常处理与线程状态管理**：
   - 该文件处理了 ART 中的异常清除（`ExceptionClear`）操作，并能够在异常清除时插入自定义的回调函数。这对于在调试或插桩时监控异常状态非常有用。
   - 例如，`recompileExceptionClearForArm64` 函数会在 `ExceptionClear` 方法中插入回调，以便在异常清除时执行自定义逻辑。

3. **ART 内部结构的解析与操作**：
   - 该文件提供了对 ART 内部结构（如 `ArtMethod`、`ArtThread` 等）的解析和操作功能。通过这些功能，可以访问和修改 ART 内部的数据结构。
   - 例如，`getArtThreadSpec` 和 `getArtMethodSpec` 函数用于获取 ART 线程和方法的内部结构信息。

4. **对象访问与遍历**：
   - 该文件提供了对 ART 对象的访问和遍历功能。通过 `makeObjectVisitorPredicate` 函数，可以创建用于遍历对象的谓词（predicate），并在匹配特定条件时执行回调。
   - 例如，`makeObjectVisitorPredicate` 函数可以用于遍历 ART 堆中的对象，并在找到特定类型的对象时执行自定义逻辑。

5. **调试与错误处理**：
   - 该文件提供了调试和错误处理功能。例如，`throwThreadStateTransitionParseError` 函数用于在解析 ART 内部状态失败时抛出错误。
   - 例如，`fixupArtQuickDeliverExceptionBug` 函数用于修复 ART 中的一个已知 bug，该 bug 在特定情况下会导致崩溃。

6. **内存管理与句柄操作**：
   - 该文件提供了对 ART 内存管理和句柄操作的支持。通过 `HandleVector` 和 `VariableSizedHandleScope` 等类，可以管理 ART 中的句柄和内存分配。
   - 例如，`VariableSizedHandleScope` 类用于管理可变大小的句柄范围，并在需要时分配和释放内存。

### 二进制底层与 Linux 内核

该文件涉及到底层的二进制操作，特别是在 ARM 和 ARM64 架构上的指令解析和重编译。以下是一些具体的例子：

- **指令解析与重编译**：`recompileExceptionClearForArm64` 函数解析 ARM64 指令，并根据特定条件（如 `ExceptionClear` 调用）插入自定义的回调函数。这涉及到对二进制指令的直接操作，包括读取、解析和生成新的指令。
- **内存保护与代码注入**：`Memory.protect` 和 `Memory.patchCode` 函数用于修改内存页的保护属性，并在内存中注入自定义的机器代码。这在调试和插桩中非常常见，特别是在需要修改运行时行为时。

### LLDB 调试示例

假设我们想要复刻 `recompileExceptionClearForArm64` 函数的功能，使用 LLDB 进行调试。以下是一个可能的 LLDB Python 脚本示例：

```python
import lldb

def recompile_exception_clear_for_arm64(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    thread = process.GetSelectedThread()
    frame = thread.GetSelectedFrame()

    # 获取 ExceptionClear 函数的地址
    exception_clear_addr = frame.FindSymbol("ExceptionClear").GetStartAddress().GetLoadAddress(target)

    # 读取指令并解析
    instruction = target.ReadMemory(exception_clear_addr, 4, lldb.SBError())
    print(f"Instruction at {hex(exception_clear_addr)}: {instruction}")

    # 插入自定义回调
    callback_addr = frame.FindSymbol("custom_callback").GetStartAddress().GetLoadAddress(target)
    target.WriteMemory(exception_clear_addr + 4, callback_addr.to_bytes(4, 'little'), lldb.SBError())

    print(f"Inserted callback at {hex(exception_clear_addr + 4)}")

# 注册 LLDB 命令
def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f recompile_exception_clear_for_arm64.recompile_exception_clear_for_arm64 recompile_exception_clear_for_arm64')
```

### 假设输入与输出

假设我们有一个 `ExceptionClear` 函数，其地址为 `0x1000`，并且我们想要在调用 `ExceptionClear` 时插入一个自定义回调函数 `custom_callback`，其地址为 `0x2000`。

- **输入**：
  - `ExceptionClear` 地址：`0x1000`
  - `custom_callback` 地址：`0x2000`

- **输出**：
  - 在 `0x1004` 处插入 `custom_callback` 的地址，使得在 `ExceptionClear` 执行时会跳转到 `custom_callback`。

### 用户常见错误

1. **指令解析错误**：如果用户尝试解析的指令格式不正确，可能会导致解析失败或生成错误的指令。例如，如果用户错误地解析了 ARM64 指令，可能会导致程序崩溃。
2. **内存保护错误**：如果用户没有正确设置内存页的保护属性，可能会导致内存访问冲突或段错误。例如，如果用户尝试在没有写权限的内存页上写入数据，会导致程序崩溃。
3. **回调函数错误**：如果用户插入的回调函数不符合预期的调用约定，可能会导致栈损坏或程序崩溃。例如，如果回调函数期望的参数与实际传递的参数不匹配，会导致未定义行为。

### 调试线索

用户操作可能会通过以下步骤到达该代码：

1. **启动调试会话**：用户启动 LLDB 调试会话，并附加到目标进程。
2. **设置断点**：用户在 `ExceptionClear` 函数上设置断点，以便在调用该函数时暂停执行。
3. **解析指令**：用户使用 LLDB 脚本解析 `ExceptionClear` 函数的指令，并确定插入回调的位置。
4. **插入回调**：用户在 `ExceptionClear` 函数中插入自定义回调函数的地址，并继续执行程序。
5. **验证结果**：用户验证回调函数是否被正确调用，并检查程序的执行结果是否符合预期。

通过以上步骤，用户可以复刻 `recompileExceptionClearForArm64` 函数的功能，并在调试过程中监控和修改程序的执行行为。
Prompt: 
```
这是目录为frida-java-bridge/lib/android.js的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第5部分，共5部分，请归纳一下它的功能

"""
  do {
      const offset = relocator.readOne();
      if (offset === 0) {
        throw new Error('Unexpected end of block');
      }
      const insn = relocator.input;
      address = insn.address;
      size = insn.size;
      const { mnemonic } = insn;

      const insnAddressId = address.toString();
      if (branchTargets.has(insnAddressId)) {
        writer.putLabel(insnAddressId);
      }

      let keep = true;

      switch (mnemonic) {
        case 'b':
          writer.putBLabel(branchLabelFromOperand(insn.operands[0]));
          keep = false;
          break;
        case 'beq.w':
          writer.putBCondLabelWide('eq', branchLabelFromOperand(insn.operands[0]));
          keep = false;
          break;
        case 'beq':
        case 'bne':
        case 'bgt':
          writer.putBCondLabelWide(mnemonic.substr(1), branchLabelFromOperand(insn.operands[0]));
          keep = false;
          break;
        case 'cbz': {
          const ops = insn.operands;
          writer.putCbzRegLabel(ops[0].value, branchLabelFromOperand(ops[1]));
          keep = false;
          break;
        }
        case 'cbnz': {
          const ops = insn.operands;
          writer.putCbnzRegLabel(ops[0].value, branchLabelFromOperand(ops[1]));
          keep = false;
          break;
        }
        /*
         * JNI::ExceptionClear(), when checked JNI is off.
         */
        case 'str':
        case 'str.w': {
          const dstValue = insn.operands[1].value;
          const dstOffset = dstValue.disp;

          if (dstOffset === exceptionOffset) {
            threadReg = dstValue.base;

            const nzcvqReg = (threadReg !== 'r4') ? 'r4' : 'r5';
            const clobberedRegs = ['r0', 'r1', 'r2', 'r3', nzcvqReg, 'r9', 'r12', 'lr'];

            writer.putPushRegs(clobberedRegs);
            writer.putMrsRegReg(nzcvqReg, 'apsr-nzcvq');

            writer.putCallAddressWithArguments(callback, [threadReg]);

            writer.putMsrRegReg('apsr-nzcvq', nzcvqReg);
            writer.putPopRegs(clobberedRegs);

            foundCore = true;
            keep = false;
          } else if (neuteredOffsets.has(dstOffset) && dstValue.base === threadReg) {
            keep = false;
          }

          break;
        }
        /*
         * CheckJNI::ExceptionClear, when checked JNI is on. Wrapper that calls JNI::ExceptionClear().
         */
        case 'ldr': {
          const [dstOp, srcOp] = insn.operands;

          if (srcOp.type === 'mem') {
            const src = srcOp.value;

            if (src.base[0] === 'r' && src.disp === ENV_VTABLE_OFFSET_EXCEPTION_CLEAR) {
              realImplReg = dstOp.value;
            }
          }

          break;
        }
        case 'blx':
          if (insn.operands[0].value === realImplReg) {
            writer.putLdrRegRegOffset('r0', 'r0', 4); // Get art::Thread * from JNIEnv *
            writer.putCallAddressWithArguments(callback, ['r0']);

            foundCore = true;
            realImplReg = null;
            keep = false;
          }

          break;
      }

      if (keep) {
        relocator.writeAll();
      } else {
        relocator.skipOne();
      }
    } while (!address.add(size).equals(end));

    relocator.dispose();
  });

  writer.dispose();

  if (!foundCore) {
    throwThreadStateTransitionParseError();
  }

  return new NativeFunction(pc.or(1), 'void', ['pointer'], nativeFunctionOptions);
}

function recompileExceptionClearForArm64 (buffer, pc, exceptionClearImpl, nextFuncImpl, exceptionOffset, neuteredOffsets, callback) {
  const blocks = {};
  const branchTargets = new Set();

  const pending = [exceptionClearImpl];
  while (pending.length > 0) {
    let current = pending.shift();

    const alreadyCovered = Object.values(blocks).some(({ begin, end }) => current.compare(begin) >= 0 && current.compare(end) < 0);
    if (alreadyCovered) {
      continue;
    }

    const blockAddressKey = current.toString();

    let block = {
      begin: current
    };
    let lastInsn = null;

    let reachedEndOfBlock = false;
    do {
      if (current.equals(nextFuncImpl)) {
        reachedEndOfBlock = true;
        break;
      }

      let insn;
      try {
        insn = Instruction.parse(current);
      } catch (e) {
        if (current.readU32() === 0x00000000) {
          reachedEndOfBlock = true;
          break;
        } else {
          throw e;
        }
      }
      lastInsn = insn;

      const existingBlock = blocks[insn.address.toString()];
      if (existingBlock !== undefined) {
        delete blocks[existingBlock.begin.toString()];
        blocks[blockAddressKey] = existingBlock;
        existingBlock.begin = block.begin;
        block = null;
        break;
      }

      let branchTarget = null;
      switch (insn.mnemonic) {
        case 'b':
          branchTarget = ptr(insn.operands[0].value);
          reachedEndOfBlock = true;
          break;
        case 'b.eq':
        case 'b.ne':
        case 'b.le':
        case 'b.gt':
          branchTarget = ptr(insn.operands[0].value);
          break;
        case 'cbz':
        case 'cbnz':
          branchTarget = ptr(insn.operands[1].value);
          break;
        case 'tbz':
        case 'tbnz':
          branchTarget = ptr(insn.operands[2].value);
          break;
        case 'ret':
          reachedEndOfBlock = true;
          break;
      }

      if (branchTarget !== null) {
        branchTargets.add(branchTarget.toString());

        pending.push(branchTarget);
        pending.sort((a, b) => a.compare(b));
      }

      current = insn.next;
    } while (!reachedEndOfBlock);

    if (block !== null) {
      block.end = lastInsn.address.add(lastInsn.size);
      blocks[blockAddressKey] = block;
    }
  }

  const blocksOrdered = Object.keys(blocks).map(key => blocks[key]);
  blocksOrdered.sort((a, b) => a.begin.compare(b.begin));

  const entryBlock = blocks[exceptionClearImpl.toString()];
  blocksOrdered.splice(blocksOrdered.indexOf(entryBlock), 1);
  blocksOrdered.unshift(entryBlock);

  const writer = new Arm64Writer(buffer, { pc });

  writer.putBLabel('performTransition');

  const invokeCallback = pc.add(writer.offset);
  writer.putPushAllXRegisters();
  writer.putCallAddressWithArguments(callback, ['x0']);
  writer.putPopAllXRegisters();
  writer.putRet();

  writer.putLabel('performTransition');

  let foundCore = false;
  let threadReg = null;
  let realImplReg = null;

  blocksOrdered.forEach(block => {
    const size = block.end.sub(block.begin).toInt32();

    const relocator = new Arm64Relocator(block.begin, writer);

    let offset;
    while ((offset = relocator.readOne()) !== 0) {
      const insn = relocator.input;
      const { mnemonic } = insn;

      const insnAddressId = insn.address.toString();
      if (branchTargets.has(insnAddressId)) {
        writer.putLabel(insnAddressId);
      }

      let keep = true;

      switch (mnemonic) {
        case 'b':
          writer.putBLabel(branchLabelFromOperand(insn.operands[0]));
          keep = false;
          break;
        case 'b.eq':
        case 'b.ne':
        case 'b.le':
        case 'b.gt':
          writer.putBCondLabel(mnemonic.substr(2), branchLabelFromOperand(insn.operands[0]));
          keep = false;
          break;
        case 'cbz': {
          const ops = insn.operands;
          writer.putCbzRegLabel(ops[0].value, branchLabelFromOperand(ops[1]));
          keep = false;
          break;
        }
        case 'cbnz': {
          const ops = insn.operands;
          writer.putCbnzRegLabel(ops[0].value, branchLabelFromOperand(ops[1]));
          keep = false;
          break;
        }
        case 'tbz': {
          const ops = insn.operands;
          writer.putTbzRegImmLabel(ops[0].value, ops[1].value.valueOf(), branchLabelFromOperand(ops[2]));
          keep = false;
          break;
        }
        case 'tbnz': {
          const ops = insn.operands;
          writer.putTbnzRegImmLabel(ops[0].value, ops[1].value.valueOf(), branchLabelFromOperand(ops[2]));
          keep = false;
          break;
        }
        /*
         * JNI::ExceptionClear(), when checked JNI is off.
         */
        case 'str': {
          const ops = insn.operands;
          const srcReg = ops[0].value;
          const dstValue = ops[1].value;
          const dstOffset = dstValue.disp;

          if (srcReg === 'xzr' && dstOffset === exceptionOffset) {
            threadReg = dstValue.base;

            writer.putPushRegReg('x0', 'lr');
            writer.putMovRegReg('x0', threadReg);
            writer.putBlImm(invokeCallback);
            writer.putPopRegReg('x0', 'lr');

            foundCore = true;
            keep = false;
          } else if (neuteredOffsets.has(dstOffset) && dstValue.base === threadReg) {
            keep = false;
          }

          break;
        }
        /*
         * CheckJNI::ExceptionClear, when checked JNI is on. Wrapper that calls JNI::ExceptionClear().
         */
        case 'ldr': {
          const ops = insn.operands;

          const src = ops[1].value;
          if (src.base[0] === 'x' && src.disp === ENV_VTABLE_OFFSET_EXCEPTION_CLEAR) {
            realImplReg = ops[0].value;
          }

          break;
        }
        case 'blr':
          if (insn.operands[0].value === realImplReg) {
            writer.putLdrRegRegOffset('x0', 'x0', 8); // Get art::Thread * from JNIEnv *
            writer.putCallAddressWithArguments(callback, ['x0']);

            foundCore = true;
            realImplReg = null;
            keep = false;
          }

          break;
      }

      if (keep) {
        relocator.writeAll();
      } else {
        relocator.skipOne();
      }

      if (offset === size) {
        break;
      }
    }

    relocator.dispose();
  });

  writer.dispose();

  if (!foundCore) {
    throwThreadStateTransitionParseError();
  }

  return new NativeFunction(pc, 'void', ['pointer'], nativeFunctionOptions);
}

function throwThreadStateTransitionParseError () {
  throw new Error('Unable to parse ART internals; please file a bug');
}

function fixupArtQuickDeliverExceptionBug (api) {
  const prettyMethod = api['art::ArtMethod::PrettyMethod'];
  if (prettyMethod === undefined) {
    return;
  }

  /*
   * There is a bug in art::Thread::QuickDeliverException() where it assumes
   * there is a Java stack frame present on the art::Thread's stack. This is
   * not the case if a native thread calls a throwing method like FindClass().
   *
   * We work around this bug here by detecting when method->PrettyMethod()
   * happens with method == nullptr.
   */
  Interceptor.attach(prettyMethod.impl, artController.hooks.ArtMethod.prettyMethod);
  Interceptor.flush();
}

function branchLabelFromOperand (op) {
  return ptr(op.value).toString();
}

function makeCxxMethodWrapperReturningPointerByValueGeneric (address, argTypes) {
  return new NativeFunction(address, 'pointer', argTypes, nativeFunctionOptions);
}

function makeCxxMethodWrapperReturningPointerByValueInFirstArg (address, argTypes) {
  const impl = new NativeFunction(address, 'void', ['pointer'].concat(argTypes), nativeFunctionOptions);
  return function () {
    const resultPtr = Memory.alloc(pointerSize);
    impl(resultPtr, ...arguments);
    return resultPtr.readPointer();
  };
}

function makeCxxMethodWrapperReturningStdStringByValue (impl, argTypes) {
  const { arch } = Process;
  switch (arch) {
    case 'ia32':
    case 'arm64': {
      let thunk;
      if (arch === 'ia32') {
        thunk = makeThunk(64, writer => {
          const argCount = 1 + argTypes.length;
          const argvSize = argCount * 4;
          writer.putSubRegImm('esp', argvSize);
          for (let i = 0; i !== argCount; i++) {
            const offset = i * 4;
            writer.putMovRegRegOffsetPtr('eax', 'esp', argvSize + 4 + offset);
            writer.putMovRegOffsetPtrReg('esp', offset, 'eax');
          }
          writer.putCallAddress(impl);
          writer.putAddRegImm('esp', argvSize - 4);
          writer.putRet();
        });
      } else {
        thunk = makeThunk(32, writer => {
          writer.putMovRegReg('x8', 'x0');
          argTypes.forEach((t, i) => {
            writer.putMovRegReg('x' + i, 'x' + (i + 1));
          });
          writer.putLdrRegAddress('x7', impl);
          writer.putBrReg('x7');
        });
      }

      const invokeThunk = new NativeFunction(thunk, 'void', ['pointer'].concat(argTypes), nativeFunctionOptions);
      const wrapper = function (...args) {
        invokeThunk(...args);
      };
      wrapper.handle = thunk;
      wrapper.impl = impl;
      return wrapper;
    }
    default: {
      const result = new NativeFunction(impl, 'void', ['pointer'].concat(argTypes), nativeFunctionOptions);
      result.impl = impl;
      return result;
    }
  }
}

class StdString {
  constructor () {
    this.handle = Memory.alloc(STD_STRING_SIZE);
  }

  dispose () {
    const [data, isTiny] = this._getData();
    if (!isTiny) {
      getApi().$delete(data);
    }
  }

  disposeToString () {
    const result = this.toString();
    this.dispose();
    return result;
  }

  toString () {
    const [data] = this._getData();
    return data.readUtf8String();
  }

  _getData () {
    const str = this.handle;
    const isTiny = (str.readU8() & 1) === 0;
    const data = isTiny ? str.add(1) : str.add(2 * pointerSize).readPointer();
    return [data, isTiny];
  }
}

class StdVector {
  $delete () {
    this.dispose();
    getApi().$delete(this);
  }

  constructor (storage, elementSize) {
    this.handle = storage;

    this._begin = storage;
    this._end = storage.add(pointerSize);
    this._storage = storage.add(2 * pointerSize);

    this._elementSize = elementSize;
  }

  init () {
    this.begin = NULL;
    this.end = NULL;
    this.storage = NULL;
  }

  dispose () {
    getApi().$delete(this.begin);
  }

  get begin () {
    return this._begin.readPointer();
  }

  set begin (value) {
    this._begin.writePointer(value);
  }

  get end () {
    return this._end.readPointer();
  }

  set end (value) {
    this._end.writePointer(value);
  }

  get storage () {
    return this._storage.readPointer();
  }

  set storage (value) {
    this._storage.writePointer(value);
  }

  get size () {
    return this.end.sub(this.begin).toInt32() / this._elementSize;
  }
}

class HandleVector extends StdVector {
  static $new () {
    const vector = new HandleVector(getApi().$new(STD_VECTOR_SIZE));
    vector.init();
    return vector;
  }

  constructor (storage) {
    super(storage, pointerSize);
  }

  get handles () {
    const result = [];

    let cur = this.begin;
    const end = this.end;
    while (!cur.equals(end)) {
      result.push(cur.readPointer());
      cur = cur.add(pointerSize);
    }

    return result;
  }
}

const BHS_OFFSET_LINK = 0;
const BHS_OFFSET_NUM_REFS = pointerSize;
const BHS_SIZE = BHS_OFFSET_NUM_REFS + 4;

const kNumReferencesVariableSized = -1;

class BaseHandleScope {
  $delete () {
    this.dispose();
    getApi().$delete(this);
  }

  constructor (storage) {
    this.handle = storage;

    this._link = storage.add(BHS_OFFSET_LINK);
    this._numberOfReferences = storage.add(BHS_OFFSET_NUM_REFS);
  }

  init (link, numberOfReferences) {
    this.link = link;
    this.numberOfReferences = numberOfReferences;
  }

  dispose () {
  }

  get link () {
    return new BaseHandleScope(this._link.readPointer());
  }

  set link (value) {
    this._link.writePointer(value);
  }

  get numberOfReferences () {
    return this._numberOfReferences.readS32();
  }

  set numberOfReferences (value) {
    this._numberOfReferences.writeS32(value);
  }
}

const VSHS_OFFSET_SELF = alignPointerOffset(BHS_SIZE);
const VSHS_OFFSET_CURRENT_SCOPE = VSHS_OFFSET_SELF + pointerSize;
const VSHS_SIZE = VSHS_OFFSET_CURRENT_SCOPE + pointerSize;

class VariableSizedHandleScope extends BaseHandleScope {
  static $new (thread, vm) {
    const scope = new VariableSizedHandleScope(getApi().$new(VSHS_SIZE));
    scope.init(thread, vm);
    return scope;
  }

  constructor (storage) {
    super(storage);

    this._self = storage.add(VSHS_OFFSET_SELF);
    this._currentScope = storage.add(VSHS_OFFSET_CURRENT_SCOPE);

    const kLocalScopeSize = 64;
    const kSizeOfReferencesPerScope = kLocalScopeSize - pointerSize - 4 - 4;
    const kNumReferencesPerScope = kSizeOfReferencesPerScope / 4;
    this._scopeLayout = FixedSizeHandleScope.layoutForCapacity(kNumReferencesPerScope);
    this._topHandleScopePtr = null;
  }

  init (thread, vm) {
    const topHandleScopePtr = thread.add(getArtThreadSpec(vm).offset.topHandleScope);
    this._topHandleScopePtr = topHandleScopePtr;

    super.init(topHandleScopePtr.readPointer(), kNumReferencesVariableSized);

    this.self = thread;
    this.currentScope = FixedSizeHandleScope.$new(this._scopeLayout);

    topHandleScopePtr.writePointer(this);
  }

  dispose () {
    this._topHandleScopePtr.writePointer(this.link);

    let scope;
    while ((scope = this.currentScope) !== null) {
      const next = scope.link;
      scope.$delete();
      this.currentScope = next;
    }
  }

  get self () {
    return this._self.readPointer();
  }

  set self (value) {
    this._self.writePointer(value);
  }

  get currentScope () {
    const storage = this._currentScope.readPointer();
    if (storage.isNull()) {
      return null;
    }
    return new FixedSizeHandleScope(storage, this._scopeLayout);
  }

  set currentScope (value) {
    this._currentScope.writePointer(value);
  }

  newHandle (object) {
    return this.currentScope.newHandle(object);
  }
}

class FixedSizeHandleScope extends BaseHandleScope {
  static $new (layout) {
    const scope = new FixedSizeHandleScope(getApi().$new(layout.size), layout);
    scope.init();
    return scope;
  }

  constructor (storage, layout) {
    super(storage);

    const { offset } = layout;
    this._refsStorage = storage.add(offset.refsStorage);
    this._pos = storage.add(offset.pos);

    this._layout = layout;
  }

  init () {
    super.init(NULL, this._layout.numberOfReferences);

    this.pos = 0;
  }

  get pos () {
    return this._pos.readU32();
  }

  set pos (value) {
    this._pos.writeU32(value);
  }

  newHandle (object) {
    const pos = this.pos;
    const handle = this._refsStorage.add(pos * 4);
    handle.writeS32(object.toInt32());
    this.pos = pos + 1;
    return handle;
  }

  static layoutForCapacity (numRefs) {
    const refsStorage = BHS_SIZE;
    const pos = refsStorage + (numRefs * 4);

    return {
      size: pos + 4,
      numberOfReferences: numRefs,
      offset: {
        refsStorage,
        pos
      }
    };
  }
}

const objectVisitorPredicateFactories = {
  arm: function (needle, onMatch) {
    const size = Process.pageSize;

    const predicate = Memory.alloc(size);

    Memory.protect(predicate, size, 'rwx');

    const onMatchCallback = new NativeCallback(onMatch, 'void', ['pointer']);
    predicate._onMatchCallback = onMatchCallback;

    const instructions = [
      0x6801, // ldr r1, [r0]
      0x4a03, // ldr r2, =needle
      0x4291, // cmp r1, r2
      0xd101, // bne mismatch
      0x4b02, // ldr r3, =onMatch
      0x4718, // bx r3
      0x4770, // bx lr
      0xbf00 // nop
    ];
    const needleOffset = instructions.length * 2;
    const onMatchOffset = needleOffset + 4;
    const codeSize = onMatchOffset + 4;

    Memory.patchCode(predicate, codeSize, function (address) {
      instructions.forEach((instruction, index) => {
        address.add(index * 2).writeU16(instruction);
      });
      address.add(needleOffset).writeS32(needle);
      address.add(onMatchOffset).writePointer(onMatchCallback);
    });

    return predicate.or(1);
  },
  arm64: function (needle, onMatch) {
    const size = Process.pageSize;

    const predicate = Memory.alloc(size);

    Memory.protect(predicate, size, 'rwx');

    const onMatchCallback = new NativeCallback(onMatch, 'void', ['pointer']);
    predicate._onMatchCallback = onMatchCallback;

    const instructions = [
      0xb9400001, // ldr w1, [x0]
      0x180000c2, // ldr w2, =needle
      0x6b02003f, // cmp w1, w2
      0x54000061, // b.ne mismatch
      0x58000083, // ldr x3, =onMatch
      0xd61f0060, // br x3
      0xd65f03c0 // ret
    ];
    const needleOffset = instructions.length * 4;
    const onMatchOffset = needleOffset + 4;
    const codeSize = onMatchOffset + 8;

    Memory.patchCode(predicate, codeSize, function (address) {
      instructions.forEach((instruction, index) => {
        address.add(index * 4).writeU32(instruction);
      });
      address.add(needleOffset).writeS32(needle);
      address.add(onMatchOffset).writePointer(onMatchCallback);
    });

    return predicate;
  }
};

function makeObjectVisitorPredicate (needle, onMatch) {
  const factory = objectVisitorPredicateFactories[Process.arch] || makeGenericObjectVisitorPredicate;
  return factory(needle, onMatch);
}

function makeGenericObjectVisitorPredicate (needle, onMatch) {
  return new NativeCallback(object => {
    const klass = object.readS32();
    if (klass === needle) {
      onMatch(object);
    }
  }, 'void', ['pointer', 'pointer']);
}

function alignPointerOffset (offset) {
  const remainder = offset % pointerSize;
  if (remainder !== 0) {
    return offset + pointerSize - remainder;
  }
  return offset;
}

module.exports = {
  getApi,
  ensureClassInitialized,
  getAndroidVersion,
  getAndroidApiLevel,
  getArtClassSpec,
  getArtMethodSpec,
  getArtFieldSpec,
  getArtThreadSpec,
  getArtThreadFromEnv,
  withRunnableArtThread,
  withAllArtThreadsSuspended,
  makeArtClassVisitor,
  makeArtClassLoaderVisitor,
  ArtStackVisitor,
  ArtMethod,
  makeMethodMangler,
  translateMethod,
  backtrace,
  revertGlobalPatches,
  deoptimizeEverything,
  deoptimizeBootImage,
  deoptimizeMethod,
  HandleVector,
  VariableSizedHandleScope,
  makeObjectVisitorPredicate,
  DVM_JNI_ENV_OFFSET_SELF
};

"""


```