# KiInjector
Kindly Injector

Simple injector for Windows ia32 process/dll. Mostly of manual map and virtual loadlibrary codes were ported and fixed from stuffs made for VC10 to GCC5. <br />
All credits for ported codes were at commentaries inside code :)<br />
Some really cool stuffs resides commented, because I didn't want to use it right now. Others are commented because I forgot to remove it. 

<br />
Build tips:<br />
1. Its depends on QT5 to be build, and remember to fixup project toolchains!!  
2. File asm.s must be compiled as a gcc object, and then be linked with injector's objectcs.
