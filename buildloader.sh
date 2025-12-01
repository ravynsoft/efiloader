#!/bin/sh

echo "---------------------------------"
echo "   Building ravynOS EFI Loader"
echo "---------------------------------"

# Mangle the architecture into what EDK uses
MACHINE=$(uname -m)
OPSYS=$(uname -s)
case ${MACHINE} in
  x86_64) MACHINE=X64 ;;
esac
echo ":: Building for ${MACHINE} on ${OPSYS}"

if ! [ -f ${LIBDIR}/BaseLib.lib ]; then
  echo ":: Building EDK2 libraries"
  (cd edk2; unset WORKSPACE EDK_TOOLS_PATH; ./EmulatorPkg/build.sh libraries)
fi

source edksetup.sh
build -t XCODE5 -a ${MACHINE} -m MdeModulePkg/Application/Loader/Loader.inf

echo ":: Finished"
