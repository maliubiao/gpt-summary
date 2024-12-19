
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
