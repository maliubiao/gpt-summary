Response:
### 功能归纳

该代码文件是Frida工具中用于与Android Java虚拟机（JVM）交互的桥接模块的一部分，主要功能包括：

1. **指令重定位与重写**：
   - 该模块通过解析和重写ARM和ARM64架构的指令，实现对Android运行时（ART）的底层操作。例如，`recompileExceptionClearForArm64`函数用于重写`ExceptionClear`方法的实现，以便在异常清除时插入自定义的回调函数。
   - 通过`Arm64Relocator`和`Arm64Writer`等工具，模块能够动态修改指令流，插入或替换特定的指令。

2. **异常处理与线程状态管理**：
   - 该模块处理与Java异常相关的操作，特别是`ExceptionClear`方法的实现。它能够检测到异常清除操作，并在适当的位置插入回调函数，以便在异常清除时执行自定义逻辑。
   - 通过`threadReg`和`realImplReg`等变量，模块能够跟踪线程状态和实际的实现方法。

3. **ART内部结构的解析与操作**：
   - 该模块能够解析ART的内部结构，如`ArtMethod`、`ArtThread`等，并通过这些结构进行操作。例如，`fixupArtQuickDeliverExceptionBug`函数用于修复ART中的一个已知bug，该bug在特定情况下会导致崩溃。
   - 通过`Interceptor`模块，模块能够拦截和修改ART的内部方法调用。

4. **内存管理与对象访问**：
   - 该模块提供了对内存管理的支持，如`StdString`和`StdVector`类，用于处理C++标准库中的字符串和向量对象。
   - 通过`HandleVector`和`VariableSizedHandleScope`等类，模块能够管理Java对象的句柄，确保在JNI调用中正确处理对象的生命周期。

5. **调试与动态插桩**：
   - 该模块支持动态插桩和调试功能，能够通过Frida的API在运行时修改和监控目标进程的行为。例如，`makeObjectVisitorPredicate`函数用于创建对象访问的谓词，能够在遍历对象时执行自定义逻辑。

### 二进制底层与Linux内核相关

- **指令重写与内存保护**：
  - 该模块通过`Memory.protect`函数修改内存页的权限，使其可写、可执行，以便动态插入和修改指令。这在底层调试和动态插桩中非常常见。
  - 例如，`objectVisitorPredicateFactories`中的代码通过直接写入内存来生成ARM和ARM64架构的指令序列，用于对象访问的谓词。

- **线程状态与寄存器操作**：
  - 该模块通过操作寄存器和线程状态来实现对ART的控制。例如，在`recompileExceptionClearForArm64`函数中，模块通过`writer.putPushRegReg`和`writer.putMovRegReg`等指令操作寄存器，确保在异常清除时正确保存和恢复线程状态。

### LLDB调试示例

假设我们想要复现该模块中的指令重写功能，可以使用LLDB的Python脚本进行调试。以下是一个示例脚本，用于在LLDB中动态修改指令：

```python
import lldb

def modify_instruction(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    thread = process.GetSelectedThread()
    frame = thread.GetSelectedFrame()

    # 获取当前指令地址
    pc = frame.GetPC()

    # 读取当前指令
    instruction = target.ReadMemory(pc, 4, lldb.SBError())
    print(f"Current instruction at {hex(pc)}: {instruction}")

    # 修改指令（例如，将指令替换为NOP）
    new_instruction = b"\x00\x00\x00\x00"  # NOP指令
    target.WriteMemory(pc, new_instruction, lldb.SBError())
    print(f"Modified instruction at {hex(pc)} to NOP")

# 注册LLDB命令
def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f modify_instruction.modify_instruction modify_instruction')
```

### 假设输入与输出

- **输入**：假设我们有一个ARM64指令流，其中包含`ExceptionClear`方法的调用。
- **输出**：通过该模块的重写功能，`ExceptionClear`方法的调用被替换为自定义的回调函数，并在回调函数中执行了额外的逻辑。

### 常见使用错误

- **内存权限错误**：在动态修改指令时，如果没有正确设置内存页的权限，可能会导致段错误（Segmentation Fault）。例如，尝试在没有`rwx`权限的内存页上写入指令会导致崩溃。
- **寄存器状态错误**：在操作寄存器时，如果没有正确保存和恢复寄存器状态，可能会导致线程状态不一致，进而引发不可预知的错误。

### 用户操作路径

1. **启动Frida**：用户通过Frida连接到目标Android进程。
2. **加载模块**：用户加载该模块，并调用相关函数（如`recompileExceptionClearForArm64`）来重写目标方法。
3. **触发目标方法**：用户通过某种方式触发目标方法（如`ExceptionClear`），模块中的回调函数被执行。
4. **调试与监控**：用户通过Frida的API监控目标进程的行为，确保自定义逻辑正确执行。

### 总结

该模块是Frida工具中用于与Android ART交互的核心部分，提供了指令重写、异常处理、内存管理等功能。通过动态插桩和调试，用户可以在运行时修改和监控目标进程的行为，实现复杂的调试和分析任务。
Prompt: 
```
这是目录为frida/subprojects/frida-java-bridge/lib/android.js的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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