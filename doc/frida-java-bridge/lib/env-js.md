Response:
### 功能归纳

`frida-java-bridge/lib/env.js` 文件是 Frida 工具中用于与 Java 虚拟机（JVM）交互的核心模块之一。它主要通过 JNI（Java Native Interface）与 Java 运行时环境进行通信，提供了对 Java 对象、类、方法、字段等的操作能力。以下是该文件的主要功能归纳：

1. **JNI 函数封装**：
   - 该文件封装了大量的 JNI 函数，如 `FindClass`、`GetMethodID`、`CallObjectMethod` 等，使得在 Frida 脚本中可以方便地调用这些 JNI 函数。
   - 通过 `proxy` 函数，动态生成 JNI 函数的调用封装，简化了 JNI 调用的复杂性。

2. **Java 对象操作**：
   - 提供了对 Java 对象的创建、引用管理（如 `NewGlobalRef`、`DeleteGlobalRef`、`DeleteLocalRef` 等）、类型检查（如 `IsInstanceOf`）等操作。
   - 支持对 Java 对象的字段进行读写操作（如 `GetField`、`SetField`、`GetStaticField`、`SetStaticField` 等）。

3. **Java 方法调用**：
   - 支持调用 Java 对象的实例方法、静态方法以及构造函数（如 `CallObjectMethod`、`CallStaticMethod`、`CallNonvirtualMethod` 等）。
   - 支持通过 JNI 调用 Java 方法，并处理返回值和异常。

4. **异常处理**：
   - 提供了对 Java 异常的捕获和处理机制（如 `ExceptionOccurred`、`ExceptionDescribe`、`ExceptionClear` 等）。
   - 当 JNI 调用抛出异常时，能够捕获异常并将其转换为 JavaScript 的 `Error` 对象。

5. **Java 类型系统支持**：
   - 提供了对 Java 类型系统的支持，包括对类、方法、字段、数组等的操作。
   - 支持获取类的名称、方法签名、字段类型等信息。

6. **内存管理**：
   - 提供了对 Java 对象的全局引用和局部引用的管理，防止内存泄漏。
   - 支持对 Java 数组的操作，如获取数组长度、读取数组元素等。

7. **调试支持**：
   - 通过 `NativeFunction` 和 `Memory` 等 Frida 提供的 API，可以直接与底层内存交互，支持对 JVM 内部的调试和分析。

### 涉及二进制底层和 Linux 内核的部分

该文件主要涉及 JNI 和 Java 虚拟机的交互，虽然不直接涉及 Linux 内核，但它通过 Frida 的底层机制与进程内存进行交互。Frida 本身是一个动态插桩工具，能够在运行时修改和监控目标进程的行为，这涉及到对进程内存的读写、函数钩子（hook）等底层操作。

#### 举例说明

- **内存读写**：通过 `Memory.allocUtf8String` 分配内存并写入字符串，然后传递给 JNI 函数。
- **函数钩子**：通过 `NativeFunction` 创建原生函数指针，调用 JNI 函数。

### 使用 LLDB 复刻调试功能

假设你想使用 LLDB 来复刻该文件中的调试功能，可以通过以下步骤实现：

1. **设置断点**：在 JNI 函数调用的地方设置断点，观察函数参数和返回值。
2. **内存查看**：使用 LLDB 查看 Java 对象的内存布局，验证字段和方法的偏移量。
3. **调用 JNI 函数**：通过 LLDB 直接调用 JNI 函数，观察其行为。

#### LLDB 示例

假设你想调试 `FindClass` 函数的调用，可以使用以下 LLDB 命令：

```lldb
# 设置断点
(lldb) b JNIEnv::FindClass

# 运行程序
(lldb) run

# 当断点命中时，查看参数
(lldb) po $arg1  # JNIEnv* env
(lldb) po $arg2  # const char* name

# 调用 FindClass 函数
(lldb) expr (void*)env->FindClass("java/lang/String")
```

### 假设输入与输出

假设你调用 `Env.prototype.findClass` 方法查找 `java/lang/String` 类：

- **输入**：`java/lang/String`
- **输出**：返回一个指向 `java.lang.String` 类的 JNI 引用（`jclass`）。

如果类不存在或 JNI 调用失败，可能会抛出异常。

### 常见使用错误

1. **内存泄漏**：
   - 用户在使用 `NewGlobalRef` 创建全局引用后，忘记调用 `DeleteGlobalRef`，导致内存泄漏。
   - 示例：`env.newGlobalRef(obj)` 后未调用 `env.deleteGlobalRef(ref)`。

2. **异常未处理**：
   - 在 JNI 调用后未检查异常，导致后续代码执行异常。
   - 示例：`env.findClass("java/lang/NonexistentClass")` 后未调用 `env.throwIfExceptionPending()`。

3. **类型不匹配**：
   - 调用 JNI 函数时传递了错误的参数类型，导致崩溃或未定义行为。
   - 示例：`env.callObjectMethod(obj, methodId, "wrongType")`，其中 `methodId` 期望一个 `int` 参数，但传递了字符串。

### 用户操作路径

1. **初始化环境**：
   - 用户通过 Frida 脚本初始化 `Env` 对象，传入 JNI 环境句柄和虚拟机实例。

2. **查找类**：
   - 用户调用 `env.findClass("java/lang/String")` 查找 `java.lang.String` 类。

3. **调用方法**：
   - 用户通过 `env.getMethodId` 获取方法 ID，然后调用 `env.callObjectMethod` 执行方法。

4. **处理异常**：
   - 如果 JNI 调用抛出异常，用户调用 `env.throwIfExceptionPending()` 捕获并处理异常。

5. **释放资源**：
   - 用户在使用完全局引用后，调用 `env.deleteGlobalRef(ref)` 释放资源。

通过这些步骤，用户可以逐步深入到 `env.js` 文件中的各个功能模块，实现与 Java 虚拟机的交互和调试。
Prompt: 
```
这是目录为frida-java-bridge/lib/env.js的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第1部分，共2部分，请归纳一下它的功能

"""
function Env (handle, vm) {
  this.handle = handle;
  this.vm = vm;
}

const pointerSize = Process.pointerSize;

const JNI_ABORT = 2;

const CALL_CONSTRUCTOR_METHOD_OFFSET = 28;

const CALL_OBJECT_METHOD_OFFSET = 34;
const CALL_BOOLEAN_METHOD_OFFSET = 37;
const CALL_BYTE_METHOD_OFFSET = 40;
const CALL_CHAR_METHOD_OFFSET = 43;
const CALL_SHORT_METHOD_OFFSET = 46;
const CALL_INT_METHOD_OFFSET = 49;
const CALL_LONG_METHOD_OFFSET = 52;
const CALL_FLOAT_METHOD_OFFSET = 55;
const CALL_DOUBLE_METHOD_OFFSET = 58;
const CALL_VOID_METHOD_OFFSET = 61;

const CALL_NONVIRTUAL_OBJECT_METHOD_OFFSET = 64;
const CALL_NONVIRTUAL_BOOLEAN_METHOD_OFFSET = 67;
const CALL_NONVIRTUAL_BYTE_METHOD_OFFSET = 70;
const CALL_NONVIRTUAL_CHAR_METHOD_OFFSET = 73;
const CALL_NONVIRTUAL_SHORT_METHOD_OFFSET = 76;
const CALL_NONVIRTUAL_INT_METHOD_OFFSET = 79;
const CALL_NONVIRTUAL_LONG_METHOD_OFFSET = 82;
const CALL_NONVIRTUAL_FLOAT_METHOD_OFFSET = 85;
const CALL_NONVIRTUAL_DOUBLE_METHOD_OFFSET = 88;
const CALL_NONVIRTUAL_VOID_METHOD_OFFSET = 91;

const CALL_STATIC_OBJECT_METHOD_OFFSET = 114;
const CALL_STATIC_BOOLEAN_METHOD_OFFSET = 117;
const CALL_STATIC_BYTE_METHOD_OFFSET = 120;
const CALL_STATIC_CHAR_METHOD_OFFSET = 123;
const CALL_STATIC_SHORT_METHOD_OFFSET = 126;
const CALL_STATIC_INT_METHOD_OFFSET = 129;
const CALL_STATIC_LONG_METHOD_OFFSET = 132;
const CALL_STATIC_FLOAT_METHOD_OFFSET = 135;
const CALL_STATIC_DOUBLE_METHOD_OFFSET = 138;
const CALL_STATIC_VOID_METHOD_OFFSET = 141;

const GET_OBJECT_FIELD_OFFSET = 95;
const GET_BOOLEAN_FIELD_OFFSET = 96;
const GET_BYTE_FIELD_OFFSET = 97;
const GET_CHAR_FIELD_OFFSET = 98;
const GET_SHORT_FIELD_OFFSET = 99;
const GET_INT_FIELD_OFFSET = 100;
const GET_LONG_FIELD_OFFSET = 101;
const GET_FLOAT_FIELD_OFFSET = 102;
const GET_DOUBLE_FIELD_OFFSET = 103;

const SET_OBJECT_FIELD_OFFSET = 104;
const SET_BOOLEAN_FIELD_OFFSET = 105;
const SET_BYTE_FIELD_OFFSET = 106;
const SET_CHAR_FIELD_OFFSET = 107;
const SET_SHORT_FIELD_OFFSET = 108;
const SET_INT_FIELD_OFFSET = 109;
const SET_LONG_FIELD_OFFSET = 110;
const SET_FLOAT_FIELD_OFFSET = 111;
const SET_DOUBLE_FIELD_OFFSET = 112;

const GET_STATIC_OBJECT_FIELD_OFFSET = 145;
const GET_STATIC_BOOLEAN_FIELD_OFFSET = 146;
const GET_STATIC_BYTE_FIELD_OFFSET = 147;
const GET_STATIC_CHAR_FIELD_OFFSET = 148;
const GET_STATIC_SHORT_FIELD_OFFSET = 149;
const GET_STATIC_INT_FIELD_OFFSET = 150;
const GET_STATIC_LONG_FIELD_OFFSET = 151;
const GET_STATIC_FLOAT_FIELD_OFFSET = 152;
const GET_STATIC_DOUBLE_FIELD_OFFSET = 153;

const SET_STATIC_OBJECT_FIELD_OFFSET = 154;
const SET_STATIC_BOOLEAN_FIELD_OFFSET = 155;
const SET_STATIC_BYTE_FIELD_OFFSET = 156;
const SET_STATIC_CHAR_FIELD_OFFSET = 157;
const SET_STATIC_SHORT_FIELD_OFFSET = 158;
const SET_STATIC_INT_FIELD_OFFSET = 159;
const SET_STATIC_LONG_FIELD_OFFSET = 160;
const SET_STATIC_FLOAT_FIELD_OFFSET = 161;
const SET_STATIC_DOUBLE_FIELD_OFFSET = 162;

const callMethodOffset = {
  pointer: CALL_OBJECT_METHOD_OFFSET,
  uint8: CALL_BOOLEAN_METHOD_OFFSET,
  int8: CALL_BYTE_METHOD_OFFSET,
  uint16: CALL_CHAR_METHOD_OFFSET,
  int16: CALL_SHORT_METHOD_OFFSET,
  int32: CALL_INT_METHOD_OFFSET,
  int64: CALL_LONG_METHOD_OFFSET,
  float: CALL_FLOAT_METHOD_OFFSET,
  double: CALL_DOUBLE_METHOD_OFFSET,
  void: CALL_VOID_METHOD_OFFSET
};

const callNonvirtualMethodOffset = {
  pointer: CALL_NONVIRTUAL_OBJECT_METHOD_OFFSET,
  uint8: CALL_NONVIRTUAL_BOOLEAN_METHOD_OFFSET,
  int8: CALL_NONVIRTUAL_BYTE_METHOD_OFFSET,
  uint16: CALL_NONVIRTUAL_CHAR_METHOD_OFFSET,
  int16: CALL_NONVIRTUAL_SHORT_METHOD_OFFSET,
  int32: CALL_NONVIRTUAL_INT_METHOD_OFFSET,
  int64: CALL_NONVIRTUAL_LONG_METHOD_OFFSET,
  float: CALL_NONVIRTUAL_FLOAT_METHOD_OFFSET,
  double: CALL_NONVIRTUAL_DOUBLE_METHOD_OFFSET,
  void: CALL_NONVIRTUAL_VOID_METHOD_OFFSET
};

const callStaticMethodOffset = {
  pointer: CALL_STATIC_OBJECT_METHOD_OFFSET,
  uint8: CALL_STATIC_BOOLEAN_METHOD_OFFSET,
  int8: CALL_STATIC_BYTE_METHOD_OFFSET,
  uint16: CALL_STATIC_CHAR_METHOD_OFFSET,
  int16: CALL_STATIC_SHORT_METHOD_OFFSET,
  int32: CALL_STATIC_INT_METHOD_OFFSET,
  int64: CALL_STATIC_LONG_METHOD_OFFSET,
  float: CALL_STATIC_FLOAT_METHOD_OFFSET,
  double: CALL_STATIC_DOUBLE_METHOD_OFFSET,
  void: CALL_STATIC_VOID_METHOD_OFFSET
};

const getFieldOffset = {
  pointer: GET_OBJECT_FIELD_OFFSET,
  uint8: GET_BOOLEAN_FIELD_OFFSET,
  int8: GET_BYTE_FIELD_OFFSET,
  uint16: GET_CHAR_FIELD_OFFSET,
  int16: GET_SHORT_FIELD_OFFSET,
  int32: GET_INT_FIELD_OFFSET,
  int64: GET_LONG_FIELD_OFFSET,
  float: GET_FLOAT_FIELD_OFFSET,
  double: GET_DOUBLE_FIELD_OFFSET
};

const setFieldOffset = {
  pointer: SET_OBJECT_FIELD_OFFSET,
  uint8: SET_BOOLEAN_FIELD_OFFSET,
  int8: SET_BYTE_FIELD_OFFSET,
  uint16: SET_CHAR_FIELD_OFFSET,
  int16: SET_SHORT_FIELD_OFFSET,
  int32: SET_INT_FIELD_OFFSET,
  int64: SET_LONG_FIELD_OFFSET,
  float: SET_FLOAT_FIELD_OFFSET,
  double: SET_DOUBLE_FIELD_OFFSET
};

const getStaticFieldOffset = {
  pointer: GET_STATIC_OBJECT_FIELD_OFFSET,
  uint8: GET_STATIC_BOOLEAN_FIELD_OFFSET,
  int8: GET_STATIC_BYTE_FIELD_OFFSET,
  uint16: GET_STATIC_CHAR_FIELD_OFFSET,
  int16: GET_STATIC_SHORT_FIELD_OFFSET,
  int32: GET_STATIC_INT_FIELD_OFFSET,
  int64: GET_STATIC_LONG_FIELD_OFFSET,
  float: GET_STATIC_FLOAT_FIELD_OFFSET,
  double: GET_STATIC_DOUBLE_FIELD_OFFSET
};

const setStaticFieldOffset = {
  pointer: SET_STATIC_OBJECT_FIELD_OFFSET,
  uint8: SET_STATIC_BOOLEAN_FIELD_OFFSET,
  int8: SET_STATIC_BYTE_FIELD_OFFSET,
  uint16: SET_STATIC_CHAR_FIELD_OFFSET,
  int16: SET_STATIC_SHORT_FIELD_OFFSET,
  int32: SET_STATIC_INT_FIELD_OFFSET,
  int64: SET_STATIC_LONG_FIELD_OFFSET,
  float: SET_STATIC_FLOAT_FIELD_OFFSET,
  double: SET_STATIC_DOUBLE_FIELD_OFFSET
};

const nativeFunctionOptions = {
  exceptions: 'propagate'
};

let cachedVtable = null;
let globalRefs = [];
Env.dispose = function (env) {
  globalRefs.forEach(env.deleteGlobalRef, env);
  globalRefs = [];
};

function register (globalRef) {
  globalRefs.push(globalRef);
  return globalRef;
}

function vtable (instance) {
  if (cachedVtable === null) {
    cachedVtable = instance.handle.readPointer();
  }
  return cachedVtable;
}

function proxy (offset, retType, argTypes, wrapper) {
  let impl = null;
  return function () {
    if (impl === null) {
      impl = new NativeFunction(vtable(this).add(offset * pointerSize).readPointer(), retType, argTypes, nativeFunctionOptions);
    }
    let args = [impl];
    args = args.concat.apply(args, arguments);
    return wrapper.apply(this, args);
  };
}

Env.prototype.getVersion = proxy(4, 'int32', ['pointer'], function (impl) {
  return impl(this.handle);
});

Env.prototype.findClass = proxy(6, 'pointer', ['pointer', 'pointer'], function (impl, name) {
  const result = impl(this.handle, Memory.allocUtf8String(name));
  this.throwIfExceptionPending();
  return result;
});

Env.prototype.throwIfExceptionPending = function () {
  const throwable = this.exceptionOccurred();
  if (throwable.isNull()) {
    return;
  }
  this.exceptionClear();
  const handle = this.newGlobalRef(throwable);
  this.deleteLocalRef(throwable);

  const description = this.vaMethod('pointer', [])(this.handle, handle, this.javaLangObject().toString);
  const descriptionStr = this.stringFromJni(description);
  this.deleteLocalRef(description);

  const error = new Error(descriptionStr);
  error.$h = handle;
  Script.bindWeak(error, makeErrorHandleDestructor(this.vm, handle));

  throw error;
};

function makeErrorHandleDestructor (vm, handle) {
  return function () {
    vm.perform(env => {
      env.deleteGlobalRef(handle);
    });
  };
}

Env.prototype.fromReflectedMethod = proxy(7, 'pointer', ['pointer', 'pointer'], function (impl, method) {
  return impl(this.handle, method);
});

Env.prototype.fromReflectedField = proxy(8, 'pointer', ['pointer', 'pointer'], function (impl, method) {
  return impl(this.handle, method);
});

Env.prototype.toReflectedMethod = proxy(9, 'pointer', ['pointer', 'pointer', 'pointer', 'uint8'], function (impl, klass, methodId, isStatic) {
  return impl(this.handle, klass, methodId, isStatic);
});

Env.prototype.getSuperclass = proxy(10, 'pointer', ['pointer', 'pointer'], function (impl, klass) {
  return impl(this.handle, klass);
});

Env.prototype.isAssignableFrom = proxy(11, 'uint8', ['pointer', 'pointer', 'pointer'], function (impl, klass1, klass2) {
  return !!impl(this.handle, klass1, klass2);
});

Env.prototype.toReflectedField = proxy(12, 'pointer', ['pointer', 'pointer', 'pointer', 'uint8'], function (impl, klass, fieldId, isStatic) {
  return impl(this.handle, klass, fieldId, isStatic);
});

Env.prototype.throw = proxy(13, 'int32', ['pointer', 'pointer'], function (impl, obj) {
  return impl(this.handle, obj);
});

Env.prototype.exceptionOccurred = proxy(15, 'pointer', ['pointer'], function (impl) {
  return impl(this.handle);
});

Env.prototype.exceptionDescribe = proxy(16, 'void', ['pointer'], function (impl) {
  impl(this.handle);
});

Env.prototype.exceptionClear = proxy(17, 'void', ['pointer'], function (impl) {
  impl(this.handle);
});

Env.prototype.pushLocalFrame = proxy(19, 'int32', ['pointer', 'int32'], function (impl, capacity) {
  return impl(this.handle, capacity);
});

Env.prototype.popLocalFrame = proxy(20, 'pointer', ['pointer', 'pointer'], function (impl, result) {
  return impl(this.handle, result);
});

Env.prototype.newGlobalRef = proxy(21, 'pointer', ['pointer', 'pointer'], function (impl, obj) {
  return impl(this.handle, obj);
});

Env.prototype.deleteGlobalRef = proxy(22, 'void', ['pointer', 'pointer'], function (impl, globalRef) {
  impl(this.handle, globalRef);
});

Env.prototype.deleteLocalRef = proxy(23, 'void', ['pointer', 'pointer'], function (impl, localRef) {
  impl(this.handle, localRef);
});

Env.prototype.isSameObject = proxy(24, 'uint8', ['pointer', 'pointer', 'pointer'], function (impl, ref1, ref2) {
  return !!impl(this.handle, ref1, ref2);
});

Env.prototype.newLocalRef = proxy(25, 'pointer', ['pointer', 'pointer'], function (impl, obj) {
  return impl(this.handle, obj);
});

Env.prototype.allocObject = proxy(27, 'pointer', ['pointer', 'pointer'], function (impl, clazz) {
  return impl(this.handle, clazz);
});

Env.prototype.getObjectClass = proxy(31, 'pointer', ['pointer', 'pointer'], function (impl, obj) {
  return impl(this.handle, obj);
});

Env.prototype.isInstanceOf = proxy(32, 'uint8', ['pointer', 'pointer', 'pointer'], function (impl, obj, klass) {
  return !!impl(this.handle, obj, klass);
});

Env.prototype.getMethodId = proxy(33, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer'], function (impl, klass, name, sig) {
  return impl(this.handle, klass, Memory.allocUtf8String(name), Memory.allocUtf8String(sig));
});

Env.prototype.getFieldId = proxy(94, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer'], function (impl, klass, name, sig) {
  return impl(this.handle, klass, Memory.allocUtf8String(name), Memory.allocUtf8String(sig));
});

Env.prototype.getIntField = proxy(100, 'int32', ['pointer', 'pointer', 'pointer'], function (impl, obj, fieldId) {
  return impl(this.handle, obj, fieldId);
});

Env.prototype.getStaticMethodId = proxy(113, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer'], function (impl, klass, name, sig) {
  return impl(this.handle, klass, Memory.allocUtf8String(name), Memory.allocUtf8String(sig));
});

Env.prototype.getStaticFieldId = proxy(144, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer'], function (impl, klass, name, sig) {
  return impl(this.handle, klass, Memory.allocUtf8String(name), Memory.allocUtf8String(sig));
});

Env.prototype.getStaticIntField = proxy(150, 'int32', ['pointer', 'pointer', 'pointer'], function (impl, obj, fieldId) {
  return impl(this.handle, obj, fieldId);
});

Env.prototype.getStringLength = proxy(164, 'int32', ['pointer', 'pointer'], function (impl, str) {
  return impl(this.handle, str);
});

Env.prototype.getStringChars = proxy(165, 'pointer', ['pointer', 'pointer', 'pointer'], function (impl, str) {
  return impl(this.handle, str, NULL);
});

Env.prototype.releaseStringChars = proxy(166, 'void', ['pointer', 'pointer', 'pointer'], function (impl, str, utf) {
  impl(this.handle, str, utf);
});

Env.prototype.newStringUtf = proxy(167, 'pointer', ['pointer', 'pointer'], function (impl, str) {
  const utf = Memory.allocUtf8String(str);
  return impl(this.handle, utf);
});

Env.prototype.getStringUtfChars = proxy(169, 'pointer', ['pointer', 'pointer', 'pointer'], function (impl, str) {
  return impl(this.handle, str, NULL);
});

Env.prototype.releaseStringUtfChars = proxy(170, 'void', ['pointer', 'pointer', 'pointer'], function (impl, str, utf) {
  impl(this.handle, str, utf);
});

Env.prototype.getArrayLength = proxy(171, 'int32', ['pointer', 'pointer'], function (impl, array) {
  return impl(this.handle, array);
});

Env.prototype.newObjectArray = proxy(172, 'pointer', ['pointer', 'int32', 'pointer', 'pointer'], function (impl, length, elementClass, initialElement) {
  return impl(this.handle, length, elementClass, initialElement);
});

Env.prototype.getObjectArrayElement = proxy(173, 'pointer', ['pointer', 'pointer', 'int32'], function (impl, array, index) {
  return impl(this.handle, array, index);
});

Env.prototype.setObjectArrayElement = proxy(174, 'void', ['pointer', 'pointer', 'int32', 'pointer'], function (impl, array, index, value) {
  impl(this.handle, array, index, value);
});

Env.prototype.newBooleanArray = proxy(175, 'pointer', ['pointer', 'int32'], function (impl, length) {
  return impl(this.handle, length);
});

Env.prototype.newByteArray = proxy(176, 'pointer', ['pointer', 'int32'], function (impl, length) {
  return impl(this.handle, length);
});

Env.prototype.newCharArray = proxy(177, 'pointer', ['pointer', 'int32'], function (impl, length) {
  return impl(this.handle, length);
});

Env.prototype.newShortArray = proxy(178, 'pointer', ['pointer', 'int32'], function (impl, length) {
  return impl(this.handle, length);
});

Env.prototype.newIntArray = proxy(179, 'pointer', ['pointer', 'int32'], function (impl, length) {
  return impl(this.handle, length);
});

Env.prototype.newLongArray = proxy(180, 'pointer', ['pointer', 'int32'], function (impl, length) {
  return impl(this.handle, length);
});

Env.prototype.newFloatArray = proxy(181, 'pointer', ['pointer', 'int32'], function (impl, length) {
  return impl(this.handle, length);
});

Env.prototype.newDoubleArray = proxy(182, 'pointer', ['pointer', 'int32'], function (impl, length) {
  return impl(this.handle, length);
});

Env.prototype.getBooleanArrayElements = proxy(183, 'pointer', ['pointer', 'pointer', 'pointer'], function (impl, array) {
  return impl(this.handle, array, NULL);
});

Env.prototype.getByteArrayElements = proxy(184, 'pointer', ['pointer', 'pointer', 'pointer'], function (impl, array) {
  return impl(this.handle, array, NULL);
});

Env.prototype.getCharArrayElements = proxy(185, 'pointer', ['pointer', 'pointer', 'pointer'], function (impl, array) {
  return impl(this.handle, array, NULL);
});

Env.prototype.getShortArrayElements = proxy(186, 'pointer', ['pointer', 'pointer', 'pointer'], function (impl, array) {
  return impl(this.handle, array, NULL);
});

Env.prototype.getIntArrayElements = proxy(187, 'pointer', ['pointer', 'pointer', 'pointer'], function (impl, array) {
  return impl(this.handle, array, NULL);
});

Env.prototype.getLongArrayElements = proxy(188, 'pointer', ['pointer', 'pointer', 'pointer'], function (impl, array) {
  return impl(this.handle, array, NULL);
});

Env.prototype.getFloatArrayElements = proxy(189, 'pointer', ['pointer', 'pointer', 'pointer'], function (impl, array) {
  return impl(this.handle, array, NULL);
});

Env.prototype.getDoubleArrayElements = proxy(190, 'pointer', ['pointer', 'pointer', 'pointer'], function (impl, array) {
  return impl(this.handle, array, NULL);
});

Env.prototype.releaseBooleanArrayElements = proxy(191, 'pointer', ['pointer', 'pointer', 'pointer', 'int32'], function (impl, array, cArray) {
  impl(this.handle, array, cArray, JNI_ABORT);
});

Env.prototype.releaseByteArrayElements = proxy(192, 'pointer', ['pointer', 'pointer', 'pointer', 'int32'], function (impl, array, cArray) {
  impl(this.handle, array, cArray, JNI_ABORT);
});

Env.prototype.releaseCharArrayElements = proxy(193, 'pointer', ['pointer', 'pointer', 'pointer', 'int32'], function (impl, array, cArray) {
  impl(this.handle, array, cArray, JNI_ABORT);
});

Env.prototype.releaseShortArrayElements = proxy(194, 'pointer', ['pointer', 'pointer', 'pointer', 'int32'], function (impl, array, cArray) {
  impl(this.handle, array, cArray, JNI_ABORT);
});

Env.prototype.releaseIntArrayElements = proxy(195, 'pointer', ['pointer', 'pointer', 'pointer', 'int32'], function (impl, array, cArray) {
  impl(this.handle, array, cArray, JNI_ABORT);
});

Env.prototype.releaseLongArrayElements = proxy(196, 'pointer', ['pointer', 'pointer', 'pointer', 'int32'], function (impl, array, cArray) {
  impl(this.handle, array, cArray, JNI_ABORT);
});

Env.prototype.releaseFloatArrayElements = proxy(197, 'pointer', ['pointer', 'pointer', 'pointer', 'int32'], function (impl, array, cArray) {
  impl(this.handle, array, cArray, JNI_ABORT);
});

Env.prototype.releaseDoubleArrayElements = proxy(198, 'pointer', ['pointer', 'pointer', 'pointer', 'int32'], function (impl, array, cArray) {
  impl(this.handle, array, cArray, JNI_ABORT);
});

Env.prototype.getByteArrayRegion = proxy(200, 'void', ['pointer', 'pointer', 'int', 'int', 'pointer'], function (impl, array, start, length, cArray) {
  impl(this.handle, array, start, length, cArray);
});

Env.prototype.setBooleanArrayRegion = proxy(207, 'void', ['pointer', 'pointer', 'int32', 'int32', 'pointer'], function (impl, array, start, length, cArray) {
  impl(this.handle, array, start, length, cArray);
});

Env.prototype.setByteArrayRegion = proxy(208, 'void', ['pointer', 'pointer', 'int32', 'int32', 'pointer'], function (impl, array, start, length, cArray) {
  impl(this.handle, array, start, length, cArray);
});

Env.prototype.setCharArrayRegion = proxy(209, 'void', ['pointer', 'pointer', 'int32', 'int32', 'pointer'], function (impl, array, start, length, cArray) {
  impl(this.handle, array, start, length, cArray);
});

Env.prototype.setShortArrayRegion = proxy(210, 'void', ['pointer', 'pointer', 'int32', 'int32', 'pointer'], function (impl, array, start, length, cArray) {
  impl(this.handle, array, start, length, cArray);
});

Env.prototype.setIntArrayRegion = proxy(211, 'void', ['pointer', 'pointer', 'int32', 'int32', 'pointer'], function (impl, array, start, length, cArray) {
  impl(this.handle, array, start, length, cArray);
});

Env.prototype.setLongArrayRegion = proxy(212, 'void', ['pointer', 'pointer', 'int32', 'int32', 'pointer'], function (impl, array, start, length, cArray) {
  impl(this.handle, array, start, length, cArray);
});

Env.prototype.setFloatArrayRegion = proxy(213, 'void', ['pointer', 'pointer', 'int32', 'int32', 'pointer'], function (impl, array, start, length, cArray) {
  impl(this.handle, array, start, length, cArray);
});

Env.prototype.setDoubleArrayRegion = proxy(214, 'void', ['pointer', 'pointer', 'int32', 'int32', 'pointer'], function (impl, array, start, length, cArray) {
  impl(this.handle, array, start, length, cArray);
});

Env.prototype.registerNatives = proxy(215, 'int32', ['pointer', 'pointer', 'pointer', 'int32'], function (impl, klass, methods, numMethods) {
  return impl(this.handle, klass, methods, numMethods);
});

Env.prototype.monitorEnter = proxy(217, 'int32', ['pointer', 'pointer'], function (impl, obj) {
  return impl(this.handle, obj);
});

Env.prototype.monitorExit = proxy(218, 'int32', ['pointer', 'pointer'], function (impl, obj) {
  return impl(this.handle, obj);
});

Env.prototype.getDirectBufferAddress = proxy(230, 'pointer', ['pointer', 'pointer'], function (impl, obj) {
  return impl(this.handle, obj);
});

Env.prototype.getObjectRefType = proxy(232, 'int32', ['pointer', 'pointer'], function (impl, ref) {
  return impl(this.handle, ref);
});

const cachedMethods = new Map();

function plainMethod (offset, retType, argTypes, options) {
  return getOrMakeMethod(this, 'p', makePlainMethod, offset, retType, argTypes, options);
}

function vaMethod (offset, retType, argTypes, options) {
  return getOrMakeMethod(this, 'v', makeVaMethod, offset, retType, argTypes, options);
}

function nonvirtualVaMethod (offset, retType, argTypes, options) {
  return getOrMakeMethod(this, 'n', makeNonvirtualVaMethod, offset, retType, argTypes, options);
}

function getOrMakeMethod (env, flavor, construct, offset, retType, argTypes, options) {
  if (options !== undefined) {
    return construct(env, offset, retType, argTypes, options);
  }

  const key = [offset, flavor, retType].concat(argTypes).join('|');
  let m = cachedMethods.get(key);
  if (m === undefined) {
    m = construct(env, offset, retType, argTypes, nativeFunctionOptions);
    cachedMethods.set(key, m);
  }
  return m;
}

function makePlainMethod (env, offset, retType, argTypes, options) {
  return new NativeFunction(
    vtable(env).add(offset * pointerSize).readPointer(),
    retType,
    ['pointer', 'pointer', 'pointer'].concat(argTypes),
    options);
}

function makeVaMethod (env, offset, retType, argTypes, options) {
  return new NativeFunction(
    vtable(env).add(offset * pointerSize).readPointer(),
    retType,
    ['pointer', 'pointer', 'pointer', '...'].concat(argTypes),
    options);
}

function makeNonvirtualVaMethod (env, offset, retType, argTypes, options) {
  return new NativeFunction(
    vtable(env).add(offset * pointerSize).readPointer(),
    retType,
    ['pointer', 'pointer', 'pointer', 'pointer', '...'].concat(argTypes),
    options);
}

Env.prototype.constructor = function (argTypes, options) {
  return vaMethod.call(this, CALL_CONSTRUCTOR_METHOD_OFFSET, 'pointer', argTypes, options);
};

Env.prototype.vaMethod = function (retType, argTypes, options) {
  const offset = callMethodOffset[retType];
  if (offset === undefined) {
    throw new Error('Unsupported type: ' + retType);
  }
  return vaMethod.call(this, offset, retType, argTypes, options);
};

Env.prototype.nonvirtualVaMethod = function (retType, argTypes, options) {
  const offset = callNonvirtualMethodOffset[retType];
  if (offset === undefined) {
    throw new Error('Unsupported type: ' + retType);
  }
  return nonvirtualVaMethod.call(this, offset, retType, argTypes, options);
};

Env.prototype.staticVaMethod = function (retType, argTypes, options) {
  const offset = callStaticMethodOffset[retType];
  if (offset === undefined) {
    throw new Error('Unsupported type: ' + retType);
  }
  return vaMethod.call(this, offset, retType, argTypes, options);
};

Env.prototype.getField = function (fieldType) {
  const offset = getFieldOffset[fieldType];
  if (offset === undefined) {
    throw new Error('Unsupported type: ' + fieldType);
  }
  return plainMethod.call(this, offset, fieldType, []);
};

Env.prototype.getStaticField = function (fieldType) {
  const offset = getStaticFieldOffset[fieldType];
  if (offset === undefined) {
    throw new Error('Unsupported type: ' + fieldType);
  }
  return plainMethod.call(this, offset, fieldType, []);
};

Env.prototype.setField = function (fieldType) {
  const offset = setFieldOffset[fieldType];
  if (offset === undefined) {
    throw new Error('Unsupported type: ' + fieldType);
  }
  return plainMethod.call(this, offset, 'void', [fieldType]);
};

Env.prototype.setStaticField = function (fieldType) {
  const offset = setStaticFieldOffset[fieldType];
  if (offset === undefined) {
    throw new Error('Unsupported type: ' + fieldType);
  }
  return plainMethod.call(this, offset, 'void', [fieldType]);
};

let javaLangClass = null;
Env.prototype.javaLangClass = function () {
  if (javaLangClass === null) {
    const handle = this.findClass('java/lang/Class');
    try {
      const get = this.getMethodId.bind(this, handle);
      javaLangClass = {
        handle: register(this.newGlobalRef(handle)),
        getName: get('getName', '()Ljava/lang/String;'),
        getSimpleName: get('getSimpleName', '()Ljava/lang/String;'),
        getGenericSuperclass: get('getGenericSuperclass', '()Ljava/lang/reflect/Type;'),
        getDeclaredConstructors: get('getDeclaredConstructors', '()[Ljava/lang/reflect/Constructor;'),
        getDeclaredMethods: get('getDeclaredMethods', '()[Ljava/lang/reflect/Method;'),
        getDeclaredFields: get('getDeclaredFields', '()[Ljava/lang/reflect/Field;'),
        isArray: get('isArray', '()Z'),
        isPrimitive: get('isPrimitive', '()Z'),
        isInterface: get('isInterface', '()Z'),
        getComponentType: get('getComponentType', '()Ljava/lang/Class;')
      };
    } finally {
      this.deleteLocalRef(handle);
    }
  }
  return javaLangClass;
};

let javaLangObject = null;
Env.prototype.javaLangObject = function () {
  if (javaLangObject === null) {
    const handle = this.findClass('java/lang/Object');
    try {
      const get = this.getMethodId.bind(this, handle);
      javaLangObject = {
        handle: register(this.newGlobalRef(handle)),
        toString: get('toString', '()Ljava/lang/String;'),
        getClass: get('getClass', '()Ljava/lang/Class;')
      };
    } finally {
      this.deleteLocalRef(handle);
    }
  }
  return javaLangObject;
};

let javaLangReflectConstructor = null;
Env.prototype.javaLangReflectConstructor = function () {
  if (javaLangReflectConstructor === null) {
    const handle = this.findClass('java/lang/reflect/Constructor');
    try {
      javaLangReflectConstructor = {
        getGenericParameterTypes: this.getMethodId(handle, 'getGenericParameterTypes', '()[Ljava/lang/reflect/Type;')
      };
    } finally {
      this.deleteLocalRef(handle);
    }
  }
  return javaLangReflectConstructor;
};

let javaLangReflectMethod = null;
Env.prototype.javaLangReflectMethod = function () {
  if (javaLangReflectMethod === null) {
    const handle = this.findClass('java/lang/reflect/Method');
    try {
      const get = this.getMethodId.bind(this, handle);
      javaLangReflectMethod = {
        getName: get('getName', '()Ljava/lang/String;'),
        getGenericParameterTypes: get('getGenericParameterTypes', '()[Ljava/lang/reflect/Type;'),
        getParameterTypes: get('getParameterTypes', '()[Ljava/lang/Class;'),
        getGenericReturnType: get('getGenericReturnType', '()Ljava/lang/reflect/Type;'),
        getGenericExceptionTypes: get('getGenericExceptionTypes', '()[Ljava/lang/reflect/Type;'),
        getModifiers: get('getModifiers', '()I'),
        isVarArgs: get('isVarArgs', '()Z')
      };
    } finally {
      this.deleteLocalRef(handle);
    }
  }
  return javaLangReflectMethod;
};

let javaLangReflectField = null;
Env.prototype.javaLangReflectField = function () {
  if (javaLangReflectField === null) {
    const handle = this.findClass('java/lang/reflect/Field');
    try {
      const get = this.getMethodId.bind(this, handle);
      javaLangReflectField = {
        getName: get('getName', '()Ljava/lang/String;'),
        getType: get('getType', '()Ljava/lang/Class;'),
        getGenericType: get('getGenericType', '()Ljava/lang/reflect/Type;'),
        getModifiers: get('getModifiers', '()I'),
        toString: get('toString', '()Ljava/lang/String;')
      };
    } finally {
      this.deleteLocalRef(handle);
    }
  }
  return javaLangReflectField;
};

let javaLangReflectTypeVariable = null;
Env.prototype.javaLangReflectTypeVariable = function () {
  if (javaLangReflectTypeVariable === null) {
    const handle = this.findClass('java/lang/reflect/TypeVariable');
    try {
      const get = this.getMethodId.bind(this, handle);
      javaLangReflectTypeVariable = {
        handle: register(this.newGlobalRef(handle)),
        getName: get('getName', '()Ljava/lang/String;'),
        getBounds: get('getBounds', '()[Ljava/lang/reflect/Type;'),
        getGenericDeclaration: get('getGenericDeclaration', '()Ljava/lang/reflect/GenericDeclaration;')
      };
    } finally {
      this.deleteLocalRef(handle);
    }
  }
  return javaLangReflectTypeVariable;
};

let javaLangReflectWildcardType = null;
Env.prototype.javaLangReflectWildcardType = function () {
  if (javaLangReflectWildcardType === null) {
    const handle = this.findClass('java/lang/reflect/WildcardType');
    try {
      const get = this.getMethodId.bind(this, handle);
      javaLangReflectWildcardType = {
        handle: register(this.newGlobalRef(handle)),
        getLowerBounds: get('getLowerBounds', '()[Ljava/lang/reflect/Type;'),
        getUpperBounds: get('getUpperBounds', '()[Ljava/lang/reflect/Type;')
      };
    } finally {
      this.deleteLocalRef(handle);
    }
  }
  return javaLangReflectWildcardType;
};

let javaLangReflectGenericArrayType = null;
Env.prototype.javaLangReflectGenericArrayType = function () {
  if (javaLangReflectGenericArrayType === null) {
    const handle = this.findClass('java/lang/reflect/GenericArrayType');
    try {
      javaLangReflectGenericArrayType = {
        handle: register(this.newGlobalRef(handle)),
        getGenericComponentType: this.getMethodId(handle, 'getGenericComponentType', '()Ljava/lang/reflect/Type;')
      };
    } finally {
      this.deleteLocalRef(handle);
    }
  }
  return javaLangReflectGenericArrayType;
};

let javaLangReflectParameterizedType = null;
Env.prototype.javaLangReflectParameterizedType = function () {
  if (javaLangReflectParameterizedType === null) {
    const handle = this.findClass('java/lang/reflect/ParameterizedType');
    try {
      const get = this.getMethodId.bind(this, handle);
      javaLangReflectParameterizedType = {
        handle: register(this.newGlobalRef(handle)),
        getActualTypeArguments: get('getActualTypeArguments', '()[Ljava/lang/reflect/Type;'),
        getRawType: get('getRawType', '()Ljava/lang/reflect/Type;'),
        getOwnerType: get('getOwnerType', '()Ljava/lang/reflect/Type;')
      };
    } finally {
      this.deleteLocalRef(handle);
    }
  }
  return javaLangReflectParameterizedType;
};

let javaLangString = null;
Env.prototype.javaLangString = function () {
  if (javaLangString === null) {
    const handle = this.findClass('java/lang/String');
    try {
      javaLangString = {
        handle: register(this.newGlobalRef(handle))
      };
    } finally {
      this.deleteLocalRef(handle);
    }
  }
  return javaLangString;
};

Env.prototype.getClassName = function (classHandle) {
  const name = this.vaMethod('pointer', [])(this.handle, classHandle, this.javaLangClass().getName);
  try {
    return this.stringFromJni(name);
  } finally {
    this.deleteLocalRef(name);
  }
};

Env.prototype.getObjectClassName = function (objHandle) {
  const jklass = this.getObjectClass(objHandle);
  try {
    return this.getClassName(jklass);
  } finally {
    this.deleteLocalRef(jklass);
  }
};

Env.prototype.getActualTypeArgument = function (type) {
  const actualTypeArguments = this.vaMethod('pointer', [])(this.handle, type, this.javaLangReflectParameterizedType().getActualTypeArguments);
  this.throwIfExceptionPending();
  if (!actualTypeArguments.isNull()) {
    try {
      return this.getTypeNameFromFirstTypeElement(actualTypeArguments);
    } finally {
      this.deleteLocalRef(actualTypeArguments);
    }
  }
};

Env.prototype.getTypeNameFromFirstTypeElement = function (typeArray) {
  const length = this.getArrayLength(typeArray);
  if (length > 0) {
    const typeArgument0 = this.getObjectArrayElement(typeArray, 0);
    try {
      return this.getTypeName(typeArgument0);
    } finally {
      this.deleteLocalRef(typeArgument0);
    }
  } else {
    // TODO
    return 'java.lang.Object';
  }
};

Env.prototype.getTypeName = function (type, getGenericsInformation) {
  const invokeObjectMethodNoArgs = this.vaMethod('pointer', []);

  if (this.isInstanceOf(type, this.javaLangClass().handle)) {
    return this.getClassName(type);
  } else if (this.isInstanceOf(type, this.javaLangReflectGenericArrayType().handle)) {
    return this.getArrayTypeName(type);
  } else if (this.isInstanceOf(type, this.javaLangReflectParameterizedType().handle)) {
    const rawType = invokeObjectMethodNoArgs(this.handle, type, this.javaLangReflectParameterizedType().getRawType);
    this.throwIfExceptionPending();
    let result;
    try {
      result = this.getTypeName(rawType);
    } finally {
      this.deleteLocalRef(rawType);
    }

    if (getGenericsInformation) {
      result += '<' + this.getActualTypeArgument(type) + '>';
    }
    return result;
  } else if (this.isInstanceOf(type, this.javaLangReflectTypeVariable().handle)) {
    // TODO
    return 'java.lang.Object';
  } else if (this.isInstanceOf(type, this.javaLangReflectWildcardType().handle)) {
    // TODO
    return 
"""


```