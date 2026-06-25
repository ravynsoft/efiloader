#!/bin/sh

echo "---------------------------------"
echo "   Building ravynOS EFI Loader"
echo "---------------------------------"

# Mangle the architecture into what EDK uses
MACHINE=$(uname -m)
OPSYS=$(uname -s)
_SDK=${SDK:-/Library/Developer/Platforms/ravynOS.platform/Developer/SDKs/ravynOS.sdk}
if [ ! -d "${_SDK}" ]; then
  _SDK=$(xcrun --sdk macosx --show-sdk-path 2>/dev/null)
fi

case ${OPSYS} in
  Darwin) TOOLCHAIN=XCODE5 ;;
  Win*) TOOLCHAIN=VS2022 ;;
  *) TOOLCHAIN=GCC5 ;;
esac

case ${MACHINE} in
  x86_64|arm64) MACHINE=X64 ;;
esac

echo ":: Building for ${MACHINE} on ${OPSYS}"
_LIBDIR=${LIBDIR:-$(pwd)/Build/Emulator${MACHINE}/DEBUG_${TOOLCHAIN}/${MACHINE}}
echo ":: Build outputs in ${_LIBDIR}"
echo ":: Using ravynOS SDK at ${_SDK}"

if ! [ -x BaseTools/Bin/VfrCompile ]; then
  echo ":: Building Base Tools"
  CC=clang CXX=clang++ make -C BaseTools/Source/C
fi

export CPATH=${_SDK}/System/Library/Frameworks/Kernel.framework/Versions/A/Headers:${_SDK}/usr/include

if ! [ -f "${_LIBDIR}/MdePkg/Library/BaseLib/BaseLib/OUTPUT/BaseLib.lib" ]; then
  echo ":: Building EDK2 libraries"
  (unset WORKSPACE EDK_TOOLS_PATH; ./EmulatorPkg/build.sh libraries)
fi

source ./edksetup.sh

# Patch Conf/tools_def.txt to use the actual mtoc location if it differs
_MTOC=$(which mtoc 2>/dev/null || echo /usr/local/bin/mtoc)
if [ -f Conf/tools_def.txt ] && [ "$_MTOC" != "/usr/local/bin/mtoc" ]; then
  sed -i '' "s|/usr/local/bin/mtoc|${_MTOC}|g" Conf/tools_def.txt
fi

build -t ${TOOLCHAIN} -a ${MACHINE} -m MdeModulePkg/Application/Loader/Loader.inf || exit 1

echo ":: Finished"
