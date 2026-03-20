cd mbedtls
#sed -i '/#define MBEDTLS_AESNI_C/d' include/mbedtls/mbedtls_config.h
git apply ../sha-ni.patch
x86intrin_path=$(dirname "$(find /usr/lib/gcc -name "x86intrin.h" -print -quit 2>/dev/null)")
for i in clean "lib -j$(nproc)"; do make CC='gcc -nostdlib -nostdinc -isystem /proc/'$$'/cwd/../../freebsd-headers -isystem '"'${x86intrin_path//"'"/"'"'"'"'"'"'"'"}'"' -O3 -march=znver2 -g -ffreestanding -ffunction-sections -fdata-sections -fvisibility=hidden' $i; done
