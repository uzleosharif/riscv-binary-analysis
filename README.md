# CPP Barebone

barebone env for cpp projects

## Build

### Pre-requisite
- Clang >= v16 / GCC >= v13
- CMake >= v3.26
- Conan >= v2.0
- Ninja >= v1.11

### Debug
```
$ conan install -pr=conanprofile.txt -of=<build> -b=missing -s=build_type=Debug .
$ cmake --preset conan-debug -G "Ninja Multi-Config"
$ cmake --build <build> --config Debug
# the executable rpg should be found in <build>/Debug/
```

### Release
```
$ conan install -pr=conanprofile.txt -of=<build> -b=missing -s=build_type=Release .
$ cmake --preset conan-release -G "Ninja Multi-Config"
$ cmake --build <build> --config Release
# the executable rpg should be found in <build>/Release/
```

