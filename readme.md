
## Principle 
1. Use clangd as the Language Server
2. Use python lsp client to query clangd
3. Use the silversearcher search results of the source code, use lsp client to query, obtain the source code
4. Use the source code to explain the function of this symbol

For example, querying the keyword `someFeatureE`, you can find the class this keyword belongs to from clangd
```c++
// Symbol Name: E, Kind: Class, Source: 
class E : public D {
public:
    void display() override {
        std::cout << "Class E" << std::endl;
    }

    ~E() override {
        std::cout << "Destructor E" << std::endl;
    }

    void someFeatureE() {
        std::cout << "Feature of Class E" << std::endl;
    }
}
```


## 原理 
1. 用clangd做于Language Server
2. 用python lsp client 查询clangd
3. 用the silversearcher搜索到的源代码结果，用lsp client查询，获得源代码
4. 用源代码，解释这个符号的作用

比如查询someFeatureE keyword，可以从clangd中找到这个keyword所属的class
```c++
//Symbol Name: E, Kind: 类, Source: 
class E : public D {
public:
    void display() override {
        std::cout << "Class E" << std::endl;
    }

    ~E() override {
        std::cout << "Destructor E" << std::endl;
    }

    void someFeatureE() {
        std::cout << "Feature of Class E" << std::endl;
    }
}
```

## gpt对查询的响应
查询prompt
```
keyword `someFeatureE` Exists in multiple source files in a large project, read them and analysis  the code,  teach me what the keyword really means, response in chinese
In file test.cpp,  content: class E : public D {
public:
    void display() override {
        std::cout << "Class E" << std::endl;
    }

    ~E() override {
        std::cout << "Destructor E" << std::endl;
    }

    void someFeatureE() {
        std::cout << "Feature of Class E" << std::endl;
    }
}
```
在分析代码后，我们可以得出关于关键字 `someFeatureE` 的一些结论。以下是详细解释：

### 文件 `test.cpp` 中的代码分析：
```cpp
class E : public D {
public:
    void display() override {
        std::cout << "Class E" << std::endl;
    }

    ~E() override {
        std::cout << "Destructor E" << std::endl;
    }

    void someFeatureE() {
        std::cout << "Feature of Class E" << std::endl;
    }
}
```

1. **类 `E` 的继承关系**：
   - 类 `E` 是从类 `D` 派生而来的（`public D`）。
   - 类 `E` 重写了 `D` 中的 `display()` 和析构函数（`~E()`）。

2. **方法 `someFeatureE()`**：
   - `someFeatureE()` 是一个成员函数，定义在类 `E` 中。
   - 该方法的功能是打印字符串 `"Feature of Class E"`。
   - 这个方法是一个普通成员函数，没有参数，也没有复杂逻辑，仅仅是一个简单的输出功能。

### 关键字 `someFeatureE` 的含义：
- **目的**：`someFeatureE` 是类 `E` 的一个特殊功能（或特性）的实现。
- **作用**：通过调用 `someFeatureE()` 方法，可以在控制台上输出 `"Feature of Class E"`，从而表明当前正在使用类 `E` 的某个特性。
- **设计意图**：这个方法可能是为了展示类 `E` 的一个独特功能，或者用于调试、测试目的。

### 总结：
关键字 `someFeatureE` 代表了类 `E` 中的一个特定功能，该功能通过简单的输出语句来展示类 `E` 的特性。虽然目前代码中没有复杂的逻辑，但它可能是未来扩展或特定功能实现的基础。

如果你在其他文件中发现类似的代码，比如另一个类中也有 `someFeatureX()` 的方法，那么可以推测这些方法的设计意图可能是为了展示每个类的独特功能或特性。
