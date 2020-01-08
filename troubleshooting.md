###troubleshooting

#### openssl problem
	
```	
error: failed to run custom build command for `scrypt v0.1.0 (/Users/wenke/rust/stargate/libra/consensus/crypto/scrypt)`

Caused by:
  process didn't exit successfully: `/Users/wenke/rust/stargate/target/debug/build/scrypt-699dcbe34a6111f6/build-script-build` (exit code: 101)
--- stderr
thread 'main' panicked at 'openssl package not found in PKG_CONFIG_PATH environment', libra/consensus/crypto/scrypt/build.rs:6:23
... ...
		
``` 
* 解决办法

``` 
export PKG_CONFIG_PATH="/usr/local/opt/openssl/lib/pkgconfig"
``` 

#### rocksdb compile problem

``` 
error: failed to run custom build command for `libtitan_sys v0.0.1 (/Volumes/jiayi/project/rust/rust-rocksdb/librocksdb_sys/libtitan_sys)`

Caused by:
  process didn't exit successfully: `/project/rust/rust-rocksdb/target/debug/build/libtitan_sys-ce30f3b48774c826/build-script-build` (exit code: 101)
--- stdout
running: "cmake" "-Wdev" "--debug-output" "/Volumes/jiayi/project/rust/rust-rocksdb/librocksdb_sys/libtitan_sys/titan" "-DROCKSDB_DIR=/Volumes/jiayi/project/rust/rust-rocksdb/librocksdb_sys/libtitan_sys/../rocksdb" "-DWITH_TITAN_TESTS=OFF" "-DWITH_TITAN_TOOLS=OFF" "-DWITH_ZLIB=ON" "-DWITH_BZ2=ON" "-DWITH_LZ4=ON" "-DWITH_ZSTD=ON" "-DWITH_SNAPPY=ON" "-DWITH_TITAN_TESTS=OFF" "-DWITH_TITAN_TOOLS=OFF" "-DCMAKE_INSTALL_PREFIX=/Volumes/jiayi/project/rust/rust-rocksdb/target/debug/build/libtitan_sys-8e96552a13478213/out" "-DCMAKE_C_FLAGS= -ffunction-sections -fdata-sections -fPIC -m64" "-DCMAKE_C_COMPILER=/usr/bin/cc" "-DCMAKE_CXX_FLAGS= -ffunction-sections -fdata-sections -fPIC -m64" "-DCMAKE_CXX_COMPILER=/usr/bin/c++" "-DCMAKE_BUILD_TYPE=Debug" "-DCMAKE_VERBOSE_MAKEFILE:BOOL=ON"
Running with debug output on.
... ...
``` 
* 解决办法：

```
参考：https://github.com/libra/libra/issues/147 
如果osx版本是Mojave，建议重装以下版本的commandLineTools：
https://download.developer.apple.com/Developer_Tools/Command_Line_Tools_macOS_10.14_for_Xcode_10.2.1.dmg/Command_Line_Tools_macOS_10.14_for_Xcode_10.2.1.dmg
或者直接升级操作系统版本到Catalina也可以解决。
```



