## ravynOS EFI Loader for XNU

A simple EFI boot loader for ravynOS.

#### Source Code

In the folder `./MdeModulePkg/Application/Loader`

#### Build Instructions

Set `SDK` to the path to your ravynOS SDK root. The default is `/Library/Developer/ravynOS.sdk`. The SDK is a product of the OS build, found under `<buildroot>/Developer/Platforms/ravynOS.platform/Developer/SDKs/ravynOS.sdk`.

From a POSIX shell, run `./buildloader.sh`. The output will be in `./Build/EmulatorX64/DEBUG_<compiler>/X64/loader.efi`. On macOS, the `<compiler>` is `XCODE5`. On Windows, it is generally `VS2022`. On most other systems it is `GCC`. 

Copy `loader.efi` to the ESP and boot.

#### Prerequisites

EFILoader is based on [TianoCore EDK2](ReadMe.rst), which will be built first on a clean build. You'll need a host with:

 * nasm
 * clang 16 or 17
 * python 3.7+


 You'll also need `mtoc` if on macOS. It's easily installed from [Brew](https://brew.sh/) with `brew install mtoc`.