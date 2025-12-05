#!/bin/sh

echo "---------------------------------"
echo "   Building ravynOS EFI Loader"
echo "---------------------------------"

# Mangle the architecture into what EDK uses
MACHINE=$(uname -m)
OPSYS=$(uname -s)
_SDK=${SDK:-/Library/Developer/ravynOS.sdk}
export CPATH=${_SDK}/System/Library/Frameworks/Kernel.framework/Versions/A/Headers:${SDK}/usr/include

case ${MACHINE} in
  x86_64) MACHINE=X64 ;;
esac
echo ":: Building for ${MACHINE} on ${OPSYS}"
_LIBDIR=${LIBDIR:-$(pwd)/Build/Emulator64/DEBUG_XCODE5/${MACHINE}}
echo ":: Build outputs in ${_LIBDIR}"
echo ":: Using ravynOS SDK at ${_SDK}"

if ! [ -f ${_LIBDIR}/BaseLib.lib ]; then
  echo ":: Building EDK2 libraries"
  (unset WORKSPACE EDK_TOOLS_PATH; ./EmulatorPkg/build.sh libraries)
fi

source edksetup.sh
build -t XCODE5 -a ${MACHINE} -m MdeModulePkg/Application/Loader/Loader.inf || exit 1

echo ":: Finished"
