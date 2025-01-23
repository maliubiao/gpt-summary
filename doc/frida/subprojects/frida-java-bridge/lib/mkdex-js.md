Response:
### 功能列举

1. **动态生成DEX文件**  
   - 根据输入的类定义生成符合Dalvik/ART规范的DEX文件，用于Android动态插桩。
2. **处理类结构**  
   - 解析类名、父类、接口、字段、方法、注解等元数据。
3. **字符串池管理**  
   - 收集所有字符串（类名、方法名、字段名等）并生成字符串池索引。
4. **类型与原型管理**  
   - 处理类型签名（如`Ljava/lang/Object;`）和方法原型（参数与返回值类型）。
5. **方法与字段编码**  
   - 生成方法ID、字段ID，处理访问标志（如`public`、`native`、`constructor`）。
6. **注解处理**  
   - 支持生成`@Throws`注解，处理注解目录和集合。
7. **调试信息注入**  
   - 为生成的构造方法添加默认调试信息（如行号表）。
8. **字节对齐与偏移计算**  
   - 确保DEX文件各段（如`header`、`data`、`map`）按4字节对齐。
9. **校验和与签名计算**  
   - 使用SHA-1生成文件签名，Adler32计算校验和。
10. **内存布局优化**  
    - 对字符串、类型、方法等按字典序排序，减少DEX体积。

---

### 执行顺序（10步）

1. **初始化模型**  
   - 调用`computeModel`解析输入的类定义，收集字符串、类型、方法等元数据。
2. **计算段偏移**  
   - 分配`header`、`string_ids`、`type_ids`、`proto_ids`等段的偏移量。
3. **填充头部信息**  
   - 写入DEX魔数、版本、文件大小、段偏移等头部元数据。
4. **生成字符串池与类型**  
   - 将字符串按UTF-8编码存储，生成类型索引。
5. **处理原型与方法**  
   - 生成方法原型（`proto_id`），处理参数类型列表。
6. **构建类定义**  
   - 写入`class_def`段，包含父类、接口、注解目录、类数据偏移。
7. **生成数据段内容**  
   - 包括注解集合、接口列表、参数字段、字符串数据、调试信息。
8. **处理类数据项**  
   - 生成`class_data_item`，编码字段、构造方法、虚方法。
9. **生成映射表**  
   - 写入`map_list`，描述DEX文件各段的位置和大小。
10. **计算校验和与签名**  
    - 使用Adler32和SHA-1更新头部校验字段。

---

### 调试示例（LLDB/Python）

假设需要调试生成的DEX头部是否合法：

```python
# lldb脚本：检查DEX头部魔数和版本
def check_dex_header(dex_buffer):
    magic = dex_buffer[0:8]  # 预期: b'dex\n035\0'
    version = dex_buffer[4:8]  # 预期: b'035\0'
    print(f"Magic: {magic}, Version: {version}")

# 在DexBuilder.build()返回后调用
dex = lldb.frame.EvaluateExpression("builder.build()").GetData().uint8
check_dex_header(dex)
```

**LLDB指令**：  
```bash
breakpoint set -f mkdex.js -l 100  # 断点在build方法结束前
run
expr dex = builder.build()
script check_dex_header(dex)
```

---

### 假设输入与输出

**输入示例**：  
```javascript
mkdex({
  name: 'com.example.Hello',
  superClass: 'java.lang.Object',
  sourceFileName: 'Hello.java',
  methods: [
    ['<init>', 'V', []],
    ['sayHello', 'V', [], ['java.io.IOException']]
  ]
})
```

**输出验证**：  
生成的DEX应包含：  
- 类`com.example.Hello`，继承`java.lang.Object`  
- 默认构造方法（`<init>`）和`sayHello`方法  
- `@Throws(java.io.IOException)`注解  
- 字符串池包含`"com/example/Hello"`、`"sayHello"`等  

---

### 常见使用错误

1. **未定义构造方法**  
   - 若用户未提供`<init>`方法，代码自动添加默认构造方法，但若父类无匹配构造方法，可能导致`NoSuchMethodError`。
2. **错误的方法签名**  
   - 如`method: ['getName', 'I', ['Ljava/lang/String;']]`（返回值应为`I`，参数应为`[Ljava/lang/String;`）。
3. **重复类型或字符串**  
   - 未去重的类型/字符串会增加DEX体积，但代码已通过`Set`自动处理。
4. **错误处理Native方法**  
   - 若方法标记为`kAccNative`但未提供本地实现，运行时抛`UnsatisfiedLinkError`。

---

### 调用链（调试线索）

1. **用户调用Frida API**  
   - 如`Java.perform()`触发动态类加载。
2. **Frida-Java-Bridge初始化**  
   - 加载`libmakedex.so`或JS模块。
3. **生成DEX规范对象**  
   - 用户定义的类结构转换为`spec`对象。
4. **调用`mkdex(spec)`**  
   - 进入`DexBuilder.build()`流程。
5. **计算模型`computeModel()`**  
   - 遍历类、方法、字段，收集元数据。
6. **分配段偏移**  
   - 计算`string_ids_offset`、`type_ids_offset`等。
7. **填充二进制Buffer**  
   - 按DEX格式逐个段写入数据。
8. **处理注解和调试信息**  
   - 生成`annotation_set_item`和`debug_info_item`。
9. **生成映射表`map_list`**  
   - 描述文件布局，供ART验证。
10. **返回DEX Buffer**  
    - 通过JNI加载到目标进程，完成插桩。
### 提示词
```
这是目录为frida/subprojects/frida-java-bridge/lib/mkdex.js的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
请列举一下它的功能, 给出执行顺序(不是行号顺序), 建议分10步,
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明调用链如何一步步的到达这里，作为调试线索，建议10步，
请用中文回复。
```

### 源代码
```javascript
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
```