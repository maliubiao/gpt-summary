Response:
### 功能概述

`mkdex.js` 是 Frida 工具中的一个模块，用于生成 DEX（Dalvik Executable）文件。DEX 文件是 Android 应用程序的核心部分，包含了应用程序的字节码、类定义、方法、字段等信息。该模块的主要功能是根据给定的类定义、方法、字段等信息，生成一个符合 DEX 文件格式的二进制文件。

### 主要功能

1. **DEX 文件结构生成**：
   - 生成 DEX 文件的头部信息（Header）。
   - 生成字符串表（String Table）、类型表（Type Table）、原型表（Proto Table）、字段表（Field Table）、方法表（Method Table）、类定义表（Class Def Table）等。
   - 生成数据段（Data Section），包括代码、调试信息、注解等。

2. **类和方法处理**：
   - 处理类的定义，包括类的访问标志、父类、接口、字段、方法等。
   - 处理方法的定义，包括方法的访问标志、参数、返回值、注解等。
   - 处理构造方法的生成，包括默认构造方法的生成。

3. **注解处理**：
   - 处理注解的定义，包括注解的类型、值、可见性等。
   - 生成注解目录（Annotation Directory）和注解集（Annotation Set）。

4. **数据对齐和校验**：
   - 对数据进行对齐处理，确保数据段的对齐要求。
   - 计算 DEX 文件的校验和（Checksum）和签名（Signature）。

### 涉及到的二进制底层和 Linux 内核

1. **DEX 文件格式**：
   - DEX 文件是 Android 应用程序的核心部分，包含了应用程序的字节码、类定义、方法、字段等信息。DEX 文件格式是 Android 虚拟机（Dalvik/ART）能够识别的二进制格式。

2. **字节序处理**：
   - 代码中使用了 `kEndianTag` 来标识 DEX 文件的字节序（小端序）。DEX 文件是小端序的，因此在生成 DEX 文件时需要确保数据的字节序正确。

3. **校验和计算**：
   - 代码中使用了 `adler32` 算法来计算 DEX 文件的校验和。`adler32` 是一种简单的校验和算法，常用于数据校验。

### 使用 LLDB 调试

假设你想使用 LLDB 来调试 DEX 文件的生成过程，可以使用以下 LLDB 命令或 Python 脚本来复刻源代码中的调试功能。

#### LLDB 命令示例

```lldb
# 设置断点
b mkdex.js:123  # 假设你想在某个特定行设置断点

# 运行程序
r

# 查看变量值
p builder.classes  # 查看 builder 对象中的 classes 属性

# 单步执行
n

# 继续执行
c
```

#### LLDB Python 脚本示例

```python
import lldb

def debug_mkdex(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    thread = process.GetSelectedThread()
    frame = thread.GetSelectedFrame()

    # 获取 builder 对象
    builder = frame.FindVariable("builder")
    classes = builder.GetChildMemberWithName("classes")

    # 打印 classes 的内容
    for i in range(classes.GetNumChildren()):
        klass = classes.GetChildAtIndex(i)
        print(f"Class {i}: {klass.GetSummary()}")

# 注册 LLDB 命令
def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f debug_mkdex.debug_mkdex debug_mkdex')
```

### 假设输入与输出

假设输入是一个包含类定义的 JSON 对象：

```json
{
  "name": "com.example.MyClass",
  "superClass": "java.lang.Object",
  "sourceFileName": "MyClass.java",
  "fields": [
    ["myField", "I"]
  ],
  "methods": [
    ["myMethod", "V", []]
  ]
}
```

输出将是一个符合 DEX 文件格式的二进制数据，包含了类定义、字段、方法等信息。

### 用户常见错误

1. **类定义错误**：
   - 用户可能忘记定义某个类或方法，导致生成的 DEX 文件不完整。
   - 例如，用户可能忘记定义构造方法，导致生成的 DEX 文件无法正确加载。

2. **字段或方法类型错误**：
   - 用户可能错误地定义了字段或方法的类型，导致生成的 DEX 文件无法正确解析。
   - 例如，用户可能错误地将字段类型定义为 `I`（整数），但实际上应该是 `Ljava/lang/String;`（字符串）。

3. **字节序错误**：
   - 用户可能在生成 DEX 文件时没有正确处理字节序，导致生成的 DEX 文件无法在 Android 设备上正确加载。

### 用户操作步骤

1. **定义类和字段**：
   - 用户首先需要定义类、字段、方法等信息，并将其传递给 `mkdex` 函数。

2. **生成 DEX 文件**：
   - 用户调用 `mkdex` 函数，生成 DEX 文件的二进制数据。

3. **调试和验证**：
   - 用户可以使用 LLDB 或其他调试工具来调试生成的 DEX 文件，确保其符合预期。

4. **加载和运行**：
   - 用户将生成的 DEX 文件加载到 Android 设备上，并运行应用程序，验证其功能是否正常。

### 调试线索

1. **类定义错误**：
   - 如果生成的 DEX 文件无法加载，用户可以通过调试工具查看 `builder.classes` 中的类定义，确保所有类和方法都已正确定义。

2. **字段或方法类型错误**：
   - 如果生成的 DEX 文件无法正确解析字段或方法，用户可以通过调试工具查看 `builder.fields` 和 `builder.methods`，确保字段和方法的类型定义正确。

3. **字节序错误**：
   - 如果生成的 DEX 文件无法在 Android 设备上正确加载，用户可以通过调试工具查看 DEX 文件的头部信息，确保字节序正确。

通过以上步骤，用户可以逐步排查问题，确保生成的 DEX 文件符合预期。
Prompt: 
```
这是目录为frida-java-bridge/lib/mkdex.js的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。

"""
const SHA1 = require('jssha/dist/sha1');

const kAccPublic = 0x0001;
const kAccNative = 0x0100;

const kAccConstructor = 0x00010000;

const kEndianTag = 0x12345678;

const kClassDefSize = 32;
const kProtoIdSize = 12;
const kFieldIdSize = 8;
const kMethodIdSize = 8;
const kTypeIdSize = 4;
const kStringIdSize = 4;
const kMapItemSize = 12;

const TYPE_HEADER_ITEM = 0;
const TYPE_STRING_ID_ITEM = 1;
const TYPE_TYPE_ID_ITEM = 2;
const TYPE_PROTO_ID_ITEM = 3;
const TYPE_FIELD_ID_ITEM = 4;
const TYPE_METHOD_ID_ITEM = 5;
const TYPE_CLASS_DEF_ITEM = 6;
const TYPE_MAP_LIST = 0x1000;
const TYPE_TYPE_LIST = 0x1001;
const TYPE_ANNOTATION_SET_ITEM = 0x1003;
const TYPE_CLASS_DATA_ITEM = 0x2000;
const TYPE_CODE_ITEM = 0x2001;
const TYPE_STRING_DATA_ITEM = 0x2002;
const TYPE_DEBUG_INFO_ITEM = 0x2003;
const TYPE_ANNOTATION_ITEM = 0x2004;
const TYPE_ANNOTATIONS_DIRECTORY_ITEM = 0x2006;

const VALUE_TYPE = 0x18;
const VALUE_ARRAY = 0x1c;

const VISIBILITY_SYSTEM = 2;

const kDefaultConstructorSize = 24;
const kDefaultConstructorDebugInfo = Buffer.from([0x03, 0x00, 0x07, 0x0e, 0x00]);

const kDalvikAnnotationTypeThrows = 'Ldalvik/annotation/Throws;';

const kNullTerminator = Buffer.from([0]);

function mkdex (spec) {
  const builder = new DexBuilder();

  const fullSpec = Object.assign({}, spec);
  builder.addClass(fullSpec);

  return builder.build();
}

class DexBuilder {
  constructor () {
    this.classes = [];
  }

  addClass (spec) {
    this.classes.push(spec);
  }

  build () {
    const model = computeModel(this.classes);

    const {
      classes,
      interfaces,
      fields,
      methods,
      protos,
      parameters,
      annotationDirectories,
      annotationSets,
      throwsAnnotations,
      types,
      strings
    } = model;

    let offset = 0;

    const headerOffset = 0;
    const checksumOffset = 8;
    const signatureOffset = 12;
    const signatureSize = 20;
    const headerSize = 0x70;
    offset += headerSize;

    const stringIdsOffset = offset;
    const stringIdsSize = strings.length * kStringIdSize;
    offset += stringIdsSize;

    const typeIdsOffset = offset;
    const typeIdsSize = types.length * kTypeIdSize;
    offset += typeIdsSize;

    const protoIdsOffset = offset;
    const protoIdsSize = protos.length * kProtoIdSize;
    offset += protoIdsSize;

    const fieldIdsOffset = offset;
    const fieldIdsSize = fields.length * kFieldIdSize;
    offset += fieldIdsSize;

    const methodIdsOffset = offset;
    const methodIdsSize = methods.length * kMethodIdSize;
    offset += methodIdsSize;

    const classDefsOffset = offset;
    const classDefsSize = classes.length * kClassDefSize;
    offset += classDefsSize;

    const dataOffset = offset;

    const annotationSetOffsets = annotationSets.map(set => {
      const setOffset = offset;
      set.offset = setOffset;

      offset += 4 + (set.items.length * 4);

      return setOffset;
    });

    const javaCodeItems = classes.reduce((result, klass) => {
      const constructorMethods = klass.classData.constructorMethods;

      constructorMethods.forEach(method => {
        const [, accessFlags, superConstructor] = method;
        if ((accessFlags & kAccNative) === 0 && superConstructor >= 0) {
          method.push(offset);
          result.push({ offset, superConstructor });
          offset += kDefaultConstructorSize;
        }
      });

      return result;
    }, []);

    annotationDirectories.forEach(dir => {
      dir.offset = offset;

      offset += 16 + (dir.methods.length * 8);
    });

    const interfaceOffsets = interfaces.map(iface => {
      offset = align(offset, 4);

      const ifaceOffset = offset;
      iface.offset = ifaceOffset;

      offset += 4 + (2 * iface.types.length);

      return ifaceOffset;
    });

    const parameterOffsets = parameters.map(param => {
      offset = align(offset, 4);

      const paramOffset = offset;
      param.offset = paramOffset;

      offset += 4 + (2 * param.types.length);

      return paramOffset;
    });

    const stringChunks = [];
    const stringOffsets = strings.map(str => {
      const strOffset = offset;

      const header = Buffer.from(createUleb128(str.length));
      const data = Buffer.from(str, 'utf8');
      const chunk = Buffer.concat([header, data, kNullTerminator]);

      stringChunks.push(chunk);

      offset += chunk.length;

      return strOffset;
    });

    const debugInfoOffsets = javaCodeItems.map(codeItem => {
      const debugOffset = offset;
      offset += kDefaultConstructorDebugInfo.length;
      return debugOffset;
    });

    const throwsAnnotationBlobs = throwsAnnotations.map(annotation => {
      const blob = makeThrowsAnnotation(annotation);

      annotation.offset = offset;

      offset += blob.length;

      return blob;
    });

    const classDataBlobs = classes.map((klass, index) => {
      klass.classData.offset = offset;

      const blob = makeClassData(klass);

      offset += blob.length;

      return blob;
    });

    const linkSize = 0;
    const linkOffset = 0;

    offset = align(offset, 4);
    const mapOffset = offset;
    const typeListLength = interfaces.length + parameters.length;
    const mapNumItems = 4 + ((fields.length > 0) ? 1 : 0) + 2 + annotationSets.length + javaCodeItems.length + annotationDirectories.length +
      ((typeListLength > 0) ? 1 : 0) + 1 + debugInfoOffsets.length + throwsAnnotations.length + classes.length + 1;
    const mapSize = 4 + (mapNumItems * kMapItemSize);
    offset += mapSize;

    const dataSize = offset - dataOffset;

    const fileSize = offset;

    const dex = Buffer.alloc(fileSize);

    dex.write('dex\n035');

    dex.writeUInt32LE(fileSize, 0x20);
    dex.writeUInt32LE(headerSize, 0x24);
    dex.writeUInt32LE(kEndianTag, 0x28);
    dex.writeUInt32LE(linkSize, 0x2c);
    dex.writeUInt32LE(linkOffset, 0x30);
    dex.writeUInt32LE(mapOffset, 0x34);
    dex.writeUInt32LE(strings.length, 0x38);
    dex.writeUInt32LE(stringIdsOffset, 0x3c);
    dex.writeUInt32LE(types.length, 0x40);
    dex.writeUInt32LE(typeIdsOffset, 0x44);
    dex.writeUInt32LE(protos.length, 0x48);
    dex.writeUInt32LE(protoIdsOffset, 0x4c);
    dex.writeUInt32LE(fields.length, 0x50);
    dex.writeUInt32LE(fields.length > 0 ? fieldIdsOffset : 0, 0x54);
    dex.writeUInt32LE(methods.length, 0x58);
    dex.writeUInt32LE(methodIdsOffset, 0x5c);
    dex.writeUInt32LE(classes.length, 0x60);
    dex.writeUInt32LE(classDefsOffset, 0x64);
    dex.writeUInt32LE(dataSize, 0x68);
    dex.writeUInt32LE(dataOffset, 0x6c);

    stringOffsets.forEach((offset, index) => {
      dex.writeUInt32LE(offset, stringIdsOffset + (index * kStringIdSize));
    });

    types.forEach((id, index) => {
      dex.writeUInt32LE(id, typeIdsOffset + (index * kTypeIdSize));
    });

    protos.forEach((proto, index) => {
      const [shortyIndex, returnTypeIndex, params] = proto;

      const protoOffset = protoIdsOffset + (index * kProtoIdSize);
      dex.writeUInt32LE(shortyIndex, protoOffset);
      dex.writeUInt32LE(returnTypeIndex, protoOffset + 4);
      dex.writeUInt32LE((params !== null) ? params.offset : 0, protoOffset + 8);
    });

    fields.forEach((field, index) => {
      const [classIndex, typeIndex, nameIndex] = field;

      const fieldOffset = fieldIdsOffset + (index * kFieldIdSize);
      dex.writeUInt16LE(classIndex, fieldOffset);
      dex.writeUInt16LE(typeIndex, fieldOffset + 2);
      dex.writeUInt32LE(nameIndex, fieldOffset + 4);
    });

    methods.forEach((method, index) => {
      const [classIndex, protoIndex, nameIndex] = method;

      const methodOffset = methodIdsOffset + (index * kMethodIdSize);
      dex.writeUInt16LE(classIndex, methodOffset);
      dex.writeUInt16LE(protoIndex, methodOffset + 2);
      dex.writeUInt32LE(nameIndex, methodOffset + 4);
    });

    classes.forEach((klass, index) => {
      const { interfaces, annotationsDirectory } = klass;
      const interfacesOffset = (interfaces !== null) ? interfaces.offset : 0;
      const annotationsOffset = (annotationsDirectory !== null) ? annotationsDirectory.offset : 0;
      const staticValuesOffset = 0;

      const classOffset = classDefsOffset + (index * kClassDefSize);
      dex.writeUInt32LE(klass.index, classOffset);
      dex.writeUInt32LE(klass.accessFlags, classOffset + 4);
      dex.writeUInt32LE(klass.superClassIndex, classOffset + 8);
      dex.writeUInt32LE(interfacesOffset, classOffset + 12);
      dex.writeUInt32LE(klass.sourceFileIndex, classOffset + 16);
      dex.writeUInt32LE(annotationsOffset, classOffset + 20);
      dex.writeUInt32LE(klass.classData.offset, classOffset + 24);
      dex.writeUInt32LE(staticValuesOffset, classOffset + 28);
    });

    annotationSets.forEach((set, index) => {
      const { items } = set;
      const setOffset = annotationSetOffsets[index];

      dex.writeUInt32LE(items.length, setOffset);
      items.forEach((item, index) => {
        dex.writeUInt32LE(item.offset, setOffset + 4 + (index * 4));
      });
    });

    javaCodeItems.forEach((codeItem, index) => {
      const { offset, superConstructor } = codeItem;

      const registersSize = 1;
      const insSize = 1;
      const outsSize = 1;
      const triesSize = 0;
      const insnsSize = 4;

      dex.writeUInt16LE(registersSize, offset);
      dex.writeUInt16LE(insSize, offset + 2);
      dex.writeUInt16LE(outsSize, offset + 4);
      dex.writeUInt16LE(triesSize, offset + 6);
      dex.writeUInt32LE(debugInfoOffsets[index], offset + 8);
      dex.writeUInt32LE(insnsSize, offset + 12);
      dex.writeUInt16LE(0x1070, offset + 16);
      dex.writeUInt16LE(superConstructor, offset + 18);
      dex.writeUInt16LE(0x0000, offset + 20);
      dex.writeUInt16LE(0x000e, offset + 22);
    });

    annotationDirectories.forEach(dir => {
      const dirOffset = dir.offset;

      const classAnnotationsOffset = 0;
      const fieldsSize = 0;
      const annotatedMethodsSize = dir.methods.length;
      const annotatedParametersSize = 0;

      dex.writeUInt32LE(classAnnotationsOffset, dirOffset);
      dex.writeUInt32LE(fieldsSize, dirOffset + 4);
      dex.writeUInt32LE(annotatedMethodsSize, dirOffset + 8);
      dex.writeUInt32LE(annotatedParametersSize, dirOffset + 12);

      dir.methods.forEach((method, index) => {
        const entryOffset = dirOffset + 16 + (index * 8);

        const [methodIndex, annotationSet] = method;
        dex.writeUInt32LE(methodIndex, entryOffset);
        dex.writeUInt32LE(annotationSet.offset, entryOffset + 4);
      });
    });

    interfaces.forEach((iface, index) => {
      const ifaceOffset = interfaceOffsets[index];

      dex.writeUInt32LE(iface.types.length, ifaceOffset);
      iface.types.forEach((type, typeIndex) => {
        dex.writeUInt16LE(type, ifaceOffset + 4 + (typeIndex * 2));
      });
    });

    parameters.forEach((param, index) => {
      const paramOffset = parameterOffsets[index];

      dex.writeUInt32LE(param.types.length, paramOffset);
      param.types.forEach((type, typeIndex) => {
        dex.writeUInt16LE(type, paramOffset + 4 + (typeIndex * 2));
      });
    });

    stringChunks.forEach((chunk, index) => {
      chunk.copy(dex, stringOffsets[index]);
    });

    debugInfoOffsets.forEach(debugInfoOffset => {
      kDefaultConstructorDebugInfo.copy(dex, debugInfoOffset);
    });

    throwsAnnotationBlobs.forEach((annotationBlob, index) => {
      annotationBlob.copy(dex, throwsAnnotations[index].offset);
    });

    classDataBlobs.forEach((classDataBlob, index) => {
      classDataBlob.copy(dex, classes[index].classData.offset);
    });

    dex.writeUInt32LE(mapNumItems, mapOffset);
    const mapItems = [
      [TYPE_HEADER_ITEM, 1, headerOffset],
      [TYPE_STRING_ID_ITEM, strings.length, stringIdsOffset],
      [TYPE_TYPE_ID_ITEM, types.length, typeIdsOffset],
      [TYPE_PROTO_ID_ITEM, protos.length, protoIdsOffset]
    ];
    if (fields.length > 0) {
      mapItems.push([TYPE_FIELD_ID_ITEM, fields.length, fieldIdsOffset]);
    }
    mapItems.push([TYPE_METHOD_ID_ITEM, methods.length, methodIdsOffset]);
    mapItems.push([TYPE_CLASS_DEF_ITEM, classes.length, classDefsOffset]);
    annotationSets.forEach((set, index) => {
      mapItems.push([TYPE_ANNOTATION_SET_ITEM, set.items.length, annotationSetOffsets[index]]);
    });
    javaCodeItems.forEach(codeItem => {
      mapItems.push([TYPE_CODE_ITEM, 1, codeItem.offset]);
    });
    annotationDirectories.forEach(dir => {
      mapItems.push([TYPE_ANNOTATIONS_DIRECTORY_ITEM, 1, dir.offset]);
    });
    if (typeListLength > 0) {
      mapItems.push([TYPE_TYPE_LIST, typeListLength, interfaceOffsets.concat(parameterOffsets)[0]]);
    }
    mapItems.push([TYPE_STRING_DATA_ITEM, strings.length, stringOffsets[0]]);
    debugInfoOffsets.forEach(debugInfoOffset => {
      mapItems.push([TYPE_DEBUG_INFO_ITEM, 1, debugInfoOffset]);
    });
    throwsAnnotations.forEach(annotation => {
      mapItems.push([TYPE_ANNOTATION_ITEM, 1, annotation.offset]);
    });
    classes.forEach(klass => {
      mapItems.push([TYPE_CLASS_DATA_ITEM, 1, klass.classData.offset]);
    });
    mapItems.push([TYPE_MAP_LIST, 1, mapOffset]);
    mapItems.forEach((item, index) => {
      const [type, size, offset] = item;

      const itemOffset = mapOffset + 4 + (index * kMapItemSize);
      dex.writeUInt16LE(type, itemOffset);
      dex.writeUInt32LE(size, itemOffset + 4);
      dex.writeUInt32LE(offset, itemOffset + 8);
    });

    const hash = new SHA1('SHA-1', 'ARRAYBUFFER');
    hash.update(dex.slice(signatureOffset + signatureSize));
    Buffer.from(hash.getHash('ARRAYBUFFER')).copy(dex, signatureOffset);

    dex.writeUInt32LE(adler32(dex, signatureOffset), checksumOffset);

    return dex;
  }
}

function makeClassData (klass) {
  const { instanceFields, constructorMethods, virtualMethods } = klass.classData;

  const staticFieldsSize = 0;

  return Buffer.from([
    staticFieldsSize
  ]
    .concat(createUleb128(instanceFields.length))
    .concat(createUleb128(constructorMethods.length))
    .concat(createUleb128(virtualMethods.length))
    .concat(instanceFields.reduce((result, [indexDiff, accessFlags]) => {
      return result
        .concat(createUleb128(indexDiff))
        .concat(createUleb128(accessFlags));
    }, []))
    .concat(constructorMethods.reduce((result, [indexDiff, accessFlags, , codeOffset]) => {
      return result
        .concat(createUleb128(indexDiff))
        .concat(createUleb128(accessFlags))
        .concat(createUleb128(codeOffset || 0));
    }, []))
    .concat(virtualMethods.reduce((result, [indexDiff, accessFlags]) => {
      const codeOffset = 0;
      return result
        .concat(createUleb128(indexDiff))
        .concat(createUleb128(accessFlags))
        .concat([codeOffset]);
    }, [])));
}

function makeThrowsAnnotation (annotation) {
  const { thrownTypes } = annotation;

  return Buffer.from([
    VISIBILITY_SYSTEM
  ]
    .concat(createUleb128(annotation.type))
    .concat([1])
    .concat(createUleb128(annotation.value))
    .concat([VALUE_ARRAY, thrownTypes.length])
    .concat(thrownTypes.reduce((result, type) => {
      result.push(VALUE_TYPE, type);
      return result;
    }, []))
  );
}

function computeModel (classes) {
  const strings = new Set();
  const types = new Set();
  const protos = {};
  const fields = [];
  const methods = [];
  const throwsAnnotations = {};
  const javaConstructors = new Set();
  const superConstructors = new Set();

  classes.forEach(klass => {
    const { name, superClass, sourceFileName } = klass;

    strings.add('this');

    strings.add(name);
    types.add(name);

    strings.add(superClass);
    types.add(superClass);

    strings.add(sourceFileName);

    klass.interfaces.forEach(iface => {
      strings.add(iface);
      types.add(iface);
    });

    klass.fields.forEach(field => {
      const [fieldName, fieldType] = field;
      strings.add(fieldName);
      strings.add(fieldType);
      types.add(fieldType);
      fields.push([klass.name, fieldType, fieldName]);
    });

    if (!klass.methods.some(([methodName]) => methodName === '<init>')) {
      klass.methods.unshift(['<init>', 'V', []]);
      javaConstructors.add(name);
    }

    klass.methods.forEach(method => {
      const [methodName, retType, argTypes, thrownTypes = []] = method;

      strings.add(methodName);

      const protoId = addProto(retType, argTypes);

      let throwsAnnotationId = null;
      if (thrownTypes.length > 0) {
        const typesNormalized = thrownTypes.slice();
        typesNormalized.sort();

        throwsAnnotationId = typesNormalized.join('|');

        let throwsAnnotation = throwsAnnotations[throwsAnnotationId];
        if (throwsAnnotation === undefined) {
          throwsAnnotation = {
            id: throwsAnnotationId,
            types: typesNormalized
          };
          throwsAnnotations[throwsAnnotationId] = throwsAnnotation;
        }

        strings.add(kDalvikAnnotationTypeThrows);
        types.add(kDalvikAnnotationTypeThrows);

        thrownTypes.forEach(type => {
          strings.add(type);
          types.add(type);
        });

        strings.add('value');
      }

      methods.push([klass.name, protoId, methodName, throwsAnnotationId]);

      if (methodName === '<init>') {
        superConstructors.add(name + '|' + protoId);
        const superConstructorId = superClass + '|' + protoId;
        if (javaConstructors.has(name) && !superConstructors.has(superConstructorId)) {
          methods.push([superClass, protoId, methodName, null]);
          superConstructors.add(superConstructorId);
        }
      }
    });
  });

  function addProto (retType, argTypes) {
    const signature = [retType].concat(argTypes);

    const id = signature.join('|');
    if (protos[id] !== undefined) {
      return id;
    }

    strings.add(retType);
    types.add(retType);
    argTypes.forEach(argType => {
      strings.add(argType);
      types.add(argType);
    });

    const shorty = signature.map(typeToShorty).join('');
    strings.add(shorty);

    protos[id] = [id, shorty, retType, argTypes];

    return id;
  }

  const stringItems = Array.from(strings);
  stringItems.sort();
  const stringToIndex = stringItems.reduce((result, string, index) => {
    result[string] = index;
    return result;
  }, {});

  const typeItems = Array.from(types).map(name => stringToIndex[name]);
  typeItems.sort(compareNumbers);
  const typeToIndex = typeItems.reduce((result, stringIndex, typeIndex) => {
    result[stringItems[stringIndex]] = typeIndex;
    return result;
  }, {});

  const literalProtoItems = Object.keys(protos).map(id => protos[id]);
  literalProtoItems.sort(compareProtoItems);
  const parameters = {};
  const protoItems = literalProtoItems.map(item => {
    const [, shorty, retType, argTypes] = item;

    let params;
    if (argTypes.length > 0) {
      const argTypesSig = argTypes.join('|');
      params = parameters[argTypesSig];
      if (params === undefined) {
        params = {
          types: argTypes.map(type => typeToIndex[type]),
          offset: -1
        };
        parameters[argTypesSig] = params;
      }
    } else {
      params = null;
    }

    return [
      stringToIndex[shorty],
      typeToIndex[retType],
      params
    ];
  });
  const protoToIndex = literalProtoItems.reduce((result, item, index) => {
    const [id] = item;
    result[id] = index;
    return result;
  }, {});
  const parameterItems = Object.keys(parameters).map(id => parameters[id]);

  const fieldItems = fields.map(field => {
    const [klass, fieldType, fieldName] = field;
    return [
      typeToIndex[klass],
      typeToIndex[fieldType],
      stringToIndex[fieldName]
    ];
  });
  fieldItems.sort(compareFieldItems);

  const methodItems = methods.map(method => {
    const [klass, protoId, name, annotationsId] = method;
    return [
      typeToIndex[klass],
      protoToIndex[protoId],
      stringToIndex[name],
      annotationsId
    ];
  });
  methodItems.sort(compareMethodItems);

  const throwsAnnotationItems = Object.keys(throwsAnnotations)
    .map(id => throwsAnnotations[id])
    .map(item => {
      return {
        id: item.id,
        type: typeToIndex[kDalvikAnnotationTypeThrows],
        value: stringToIndex.value,
        thrownTypes: item.types.map(type => typeToIndex[type]),
        offset: -1
      };
    });

  const annotationSetItems = throwsAnnotationItems.map(item => {
    return {
      id: item.id,
      items: [item],
      offset: -1
    };
  });
  const annotationSetIdToIndex = annotationSetItems.reduce((result, item, index) => {
    result[item.id] = index;
    return result;
  }, {});

  const interfaceLists = {};
  const annotationDirectories = [];
  const classItems = classes.map(klass => {
    const classIndex = typeToIndex[klass.name];
    const accessFlags = kAccPublic;
    const superClassIndex = typeToIndex[klass.superClass];

    let ifaceList;
    const ifaces = klass.interfaces.map(type => typeToIndex[type]);
    if (ifaces.length > 0) {
      ifaces.sort(compareNumbers);
      const ifacesId = ifaces.join('|');
      ifaceList = interfaceLists[ifacesId];
      if (ifaceList === undefined) {
        ifaceList = {
          types: ifaces,
          offset: -1
        };
        interfaceLists[ifacesId] = ifaceList;
      }
    } else {
      ifaceList = null;
    }

    const sourceFileIndex = stringToIndex[klass.sourceFileName];

    const classMethods = methodItems.reduce((result, method, index) => {
      const [holder, protoIndex, name, annotationsId] = method;
      if (holder === classIndex) {
        result.push([index, name, annotationsId, protoIndex]);
      }
      return result;
    }, []);

    let annotationsDirectory = null;
    const methodAnnotations = classMethods
      .filter(([, , annotationsId]) => {
        return annotationsId !== null;
      })
      .map(([index, , annotationsId]) => {
        return [index, annotationSetItems[annotationSetIdToIndex[annotationsId]]];
      });
    if (methodAnnotations.length > 0) {
      annotationsDirectory = {
        methods: methodAnnotations,
        offset: -1
      };
      annotationDirectories.push(annotationsDirectory);
    }

    const instanceFields = fieldItems.reduce((result, field, index) => {
      const [holder] = field;
      if (holder === classIndex) {
        result.push([index > 0 ? 1 : 0, kAccPublic]);
      }
      return result;
    }, []);

    const constructorNameIndex = stringToIndex['<init>'];
    const constructorMethods = classMethods
      .filter(([, name]) => name === constructorNameIndex)
      .map(([index, , , protoIndex]) => {
        if (javaConstructors.has(klass.name)) {
          let superConstructor = -1;
          const numMethodItems = methodItems.length;
          for (let i = 0; i !== numMethodItems; i++) {
            const [methodClass, methodProto, methodName] = methodItems[i];
            if (methodClass === superClassIndex && methodName === constructorNameIndex && methodProto === protoIndex) {
              superConstructor = i;
              break;
            }
          }
          return [index, kAccPublic | kAccConstructor, superConstructor];
        } else {
          return [index, kAccPublic | kAccConstructor | kAccNative, -1];
        }
      });
    const virtualMethods = compressClassMethodIndexes(classMethods
      .filter(([, name]) => name !== constructorNameIndex)
      .map(([index]) => {
        return [index, kAccPublic | kAccNative];
      }));

    const classData = {
      instanceFields,
      constructorMethods,
      virtualMethods,
      offset: -1
    };

    return {
      index: classIndex,
      accessFlags,
      superClassIndex,
      interfaces: ifaceList,
      sourceFileIndex,
      annotationsDirectory,
      classData
    };
  });
  const interfaceItems = Object.keys(interfaceLists).map(id => interfaceLists[id]);

  return {
    classes: classItems,
    interfaces: interfaceItems,
    fields: fieldItems,
    methods: methodItems,
    protos: protoItems,
    parameters: parameterItems,
    annotationDirectories,
    annotationSets: annotationSetItems,
    throwsAnnotations: throwsAnnotationItems,
    types: typeItems,
    strings: stringItems
  };
}

function compressClassMethodIndexes (items) {
  let previousIndex = 0;
  return items.map(([index, accessFlags], elementIndex) => {
    let result;
    if (elementIndex === 0) {
      result = [index, accessFlags];
    } else {
      result = [index - previousIndex, accessFlags];
    }
    previousIndex = index;
    return result;
  });
}

function compareNumbers (a, b) {
  return a - b;
}

function compareProtoItems (a, b) {
  const [, , aRetType, aArgTypes] = a;
  const [, , bRetType, bArgTypes] = b;

  if (aRetType < bRetType) {
    return -1;
  }
  if (aRetType > bRetType) {
    return 1;
  }

  const aArgTypesSig = aArgTypes.join('|');
  const bArgTypesSig = bArgTypes.join('|');
  if (aArgTypesSig < bArgTypesSig) {
    return -1;
  }
  if (aArgTypesSig > bArgTypesSig) {
    return 1;
  }
  return 0;
}

function compareFieldItems (a, b) {
  const [aClass, aType, aName] = a;
  const [bClass, bType, bName] = b;

  if (aClass !== bClass) {
    return aClass - bClass;
  }

  if (aName !== bName) {
    return aName - bName;
  }

  return aType - bType;
}

function compareMethodItems (a, b) {
  const [aClass, aProto, aName] = a;
  const [bClass, bProto, bName] = b;

  if (aClass !== bClass) {
    return aClass - bClass;
  }

  if (aName !== bName) {
    return aName - bName;
  }

  return aProto - bProto;
}

function typeToShorty (type) {
  const firstCharacter = type[0];
  return (firstCharacter === 'L' || firstCharacter === '[') ? 'L' : type;
}

function createUleb128 (value) {
  if (value <= 0x7f) {
    return [value];
  }

  const result = [];
  let moreSlicesNeeded = false;

  do {
    let slice = value & 0x7f;

    value >>= 7;
    moreSlicesNeeded = value !== 0;

    if (moreSlicesNeeded) {
      slice |= 0x80;
    }

    result.push(slice);
  } while (moreSlicesNeeded);

  return result;
}

function align (value, alignment) {
  const alignmentDelta = value % alignment;
  if (alignmentDelta === 0) {
    return value;
  }
  return value + alignment - alignmentDelta;
}

function adler32 (buffer, offset) {
  let a = 1;
  let b = 0;

  const length = buffer.length;
  for (let i = offset; i < length; i++) {
    a = (a + buffer[i]) % 65521;
    b = (b + a) % 65521;
  }

  return ((b << 16) | a) >>> 0;
}

module.exports = mkdex;

"""

```