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
