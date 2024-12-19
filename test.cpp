#include <iostream>
#include <vector>
#include <algorithm>
#include <ctime>
#include <cstdlib>
#include <chrono>
#include <random>


// Function to partition the array
int my_partition(std::vector<double>& arr, int low, int high) { // 修改这里
    double pivot = arr[high];
    int i = low - 1;
    for (int j = low; j < high; j++) {
        if (arr[j] < pivot) {
            i++;
            std::swap(arr[i], arr[j]);
        }
    }
    std::swap(arr[i + 1], arr[high]);
    return i + 1;
}
// Function to perform quicksort
void quicksort(std::vector<double>& arr, int low, int high) {
    if (low < high) {
        int pivot = my_partition(arr, low, high); // 修改这里
        quicksort(arr, low, pivot - 1);
        quicksort(arr, pivot + 1, high);
    }
}


class C {
public:
    virtual void display() {
        std::cout << "Class C" << std::endl;
    }

    virtual ~C() {
        std::cout << "Destructor C" << std::endl;
    }

    void someFeatureC() {
        std::cout << "Feature of Class C" << std::endl;
    }
};

class D {
public:
    virtual void display() {
        std::cout << "Class D" << std::endl;
    }

    virtual ~D() {
        std::cout << "Destructor D" << std::endl;
    }

    void someFeatureD() {
        std::cout << "Feature of Class D" << std::endl;
    }
};

class B : public C {
public:
    void display() override {
        std::cout << "Class B" << std::endl;
    }

    ~B() override {
        std::cout << "Destructor B" << std::endl;
    }

    void someFeatureB() {
        std::cout << "Feature of Class B" << std::endl;
    }
};

class A : public B {
public:
    void display() override {
        std::cout << "Class A" << std::endl;
    }

    ~A() override {
        std::cout << "Destructor A" << std::endl;
    }

    void someFeatureA() {
        std::cout << "Feature of Class A" << std::endl;
    }
};

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
};


// Sample code for C++ template features for compiler debug purpose

// Template class example
template <typename T>
class Box {
public:
    Box(T value) : content(value) {}

    T getContent() const {
        return content;
    }

private:
    T content;
};

// Template function example
template <typename T>
T add(T a, T b) {
    return a + b;
}

// Template specialization example
template <>
class Box<char> {
public:
    Box(char value) : content(value) {}

    char getContent() const {
        return content;
    }

private:
    char content;
};

// Variadic template example
template <typename T>
void print(T t) {
    std::cout << t << std::endl;
}

template <typename T, typename... Args>
void print(T t, Args... args) {
    std::cout << t << ", ";
    print(args...);
}


// 宏定义示例，用于编译器调试

// 简单的宏定义
#define PI 3.14159

// 带参数的宏定义
#define SQUARE(x) ((x) * (x))

// 多行宏定义
#define DEBUG_PRINT(msg) \
    do { \
        std::cout << "Debug: " << msg << std::endl; \
    } while (0)

// 条件编译宏
#ifdef _DEBUG
#define LOG(msg) \
    do { \
        std::cout << "Log: " << msg << std::endl; \
    } while (0)
#else
#define LOG(msg)
#endif

// 可变参数宏
#define ERROR_PRINT(fmt, ...) \
    do { \
        std::cerr << "Error: " << fmt << std::endl; \
        std::cerr << "File: " << __FILE__ << ", Line: " << __LINE__ << std::endl; \
        std::cerr << "Function: " << __FUNCTION__ << std::endl; \
        std::cerr << "Arguments: " << __VA_ARGS__ << std::endl; \
    } while (0)

// 宏用于类型检查
#define CHECK_TYPE(var, type) \
    static_assert(std::is_same<decltype(var), type>::value, "Type mismatch")


void printCompilerInfo() {
    // 编译器内置特性示例，用于调试

    // __func__：当前函数名
    DEBUG_PRINT(__func__);

    // __FILE__：当前文件名
    DEBUG_PRINT(__FILE__);

    // __LINE__：当前行号
    DEBUG_PRINT(__LINE__);

    // __DATE__：编译日期
    DEBUG_PRINT(__DATE__);

    // __TIME__：编译时间
    DEBUG_PRINT(__TIME__);

    // __cplusplus：C++标准版本
    DEBUG_PRINT(__cplusplus);

    // __STDC__：是否遵循ANSI C标准
#ifdef __STDC__
    DEBUG_PRINT("遵循ANSI C标准");
#else
    DEBUG_PRINT("不遵循ANSI C标准");
#endif

    // __GNUC__：GCC编译器版本
#ifdef __GNUC__
    DEBUG_PRINT("使用GCC编译器");
    DEBUG_PRINT(__GNUC__);
#endif

    // __clang__：Clang编译器版本
#ifdef __clang__
    DEBUG_PRINT("使用Clang编译器");
    DEBUG_PRINT(__clang__);
#endif

    // __VERSION__：编译器版本字符串
    DEBUG_PRINT(__VERSION__);
    
    // 获取变量类型信息
    std::vector<double> arr(1000); // init arr
    std::cout << "Type of arr: " << typeid(arr).name() << std::endl;
    std::cout << "Type of arr[0]: " << typeid(arr[0]).name() << std::endl;
}



int main() {
    // Initialize array with 1000 elements from 1.0 to 1000.0
    std::vector<double> arr(1000);
    for (int i = 0; i < 1000; i++) {
        arr[i] = static_cast<double>(i + 1);
    }
    unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
    std::default_random_engine rng(seed);

    // Shuffle the array
    std::shuffle(arr.begin(), arr.end(), rng);

    // Print the shuffled array
    std::cout << "Shuffled array:" << std::endl;
    for (double num : arr) {
        std::cout << num << " ";
    }
    std::cout << std::endl;

    // Sort the array using quicksort
    quicksort(arr, 0, arr.size() - 1);

    // Print the sorted array
    std::cout << "Sorted array:" << std::endl;
    for (double num : arr) {
        std::cout << num << " ";
    }
    std::cout << std::endl;

    return 0;
}
