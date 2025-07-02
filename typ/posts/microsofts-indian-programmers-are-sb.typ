#import "@preview/shiroa:0.1.0": *
#import "@preview/typst-apollo:0.1.0": pages
#import pages: *
#import "@preview/shiroa:0.1.0": get-page-width, target, is-web-target, is-pdf-target, plain-text

#import "@preview/unequivocal-ams:0.1.0": theorem, proof

#show: project.with(
  title: "记分析 ucrtbase.dll 中的 pow 函数计算 -1 的偶次幂时的错误",
  authors: (
    (
      name: "purofle",
      email: "purofle@gmail.com",
    ),
  ),
)

== 起因

在 Hacker News 上看到了这个 #link("https://github.com/dotnet/runtime/issues/117233")[`Issue（C# Math.Pow(-1, 2) doesn't output correct value on Windows 11 Insider Preview, Canary channel (27881.1000) #117233）`]，感觉非常有意思，于是找来使用 Windows Insider 27881 的群友测试。

== 复现

复现代码如下：
```c
#include <stdio.h>
#include <windows.h>

int main(void) {
    HINSTANCE hInst = LoadLibrary("C:\\Windows\\System32\\ucrtbase.dll");
    HINSTANCE hInst2 = LoadLibrary("C:\\Users\\purofle\\Downloads\\Telegram Desktop\\ucrtbase.dll"); // Windows Insider 27881
    FARPROC fp = GetProcAddress(hInst, "pow");
    FARPROC fp2 = GetProcAddress(hInst2, "pow");
    double (*powFunc)(double, double) = (double (*)(double, double))fp;
    double (*powFunc2)(double, double) = (double (*)(double, double))fp2;
    // for (int i = -1000; i < 5000; i++) {
    //     for (int j = -1000; j < 5000; j++) {
    //         double result = powFunc(i, j);
    //         double result2 = powFunc2(i, j);
    //         if (result != result2) {
    //             printf("Mismatch at i = %d, j = %d: result = %f, result2 = %f\n", i, j, result, result2);
    //         }
    //     }
    // }
    double result = powFunc(-1, 2);
    double result2 = powFunc2(-1, 2);
    printf("Result from ucrtbase.dll: %f\n", result);
    printf("Result from ucrtbase.dll (Insider): %f\n", result2);
    return 0;
}
```

经过运行后得知，所有 i=-1 ，即底数为 -1 时的计算使用 Windows Insider 都会出错，于是使用 Ghidra 反编译 Windows Insider 27881 版本的 ucrtbase.dll，得到以下 C 文件：https://gist.github.com/purofle/33a81f5b6f4de15bc7f53a2214577c7c，于是进行分析。

== 简单分析
首先我们遇到的第一个大 if 在 51 行：
```c
...
uVar10 = (uint)((ulonglong)_X >> 0x20);
uVar7 = uVar10 >> 0x14;
uVar2 = (uint)((ulonglong)_Y >> 0x20);
uVar9 = uVar2 >> 0x14;
dVa  r13 = _X;
if ((0x7fd < uVar7 - 1) || (0x7f < (uVar9 & 0x7ff) - 0x3be)) { // 这是 51 行
...
```
这里的 `(0xfd < uVar7 - 1)` 化简后为 `(uVar7 > 0x7fe)`，其中 `0x7fe` 为浮点数可保存的最大值。那么我们的 `_X` 也就是底数 `-1` 的二进制表示为 `0xBFF0000000000000`，经过计算后，`uVar7` 的值为 `0xbff`，因此 `(0x7fd < 0xbfe)` 为真，进入到了这个特殊运算分支。

接下来我们看到了多个 `if` 语句，用来判断特殊值的情况，而我们的问题就出在 94 行这么一个判断的内部：
```c
if (((ulonglong)_X & 0x8000000000000000) != 0) {
```
这段 if 语句判断了 `_X` 的符号位是否为 1，也就是判断底数是否为负数。由于我们的 `_X` 是 `-1`，因此这个判断为真，进入了这个分支。

首先，在 95 行中有这么一句：`uVar7 = uVar2 >> 0x14 & 0x7ff`，它将 `_Y` 的 11 位（指数部分）提取出来，并储存在 `uVar7` 中。
我们计算得知，当 `_Y` 为 `2` 时，`uVar7` 的值为 `0x400`，而 `0x434 < 0x400 < 0x3ff`，所以进入到了 101 行的 `if` 中：
```c
if (uVar7 < 0x434) { // 101 行
    uVar8 = 1L << ((ulonglong)(0x433 - uVar7) & 0x3f);
    if (((ulonglong)_Y & uVar8 - 1) != 0) goto LAB_180066199;
    iVar3 = 2 - (uint)((uVar8 & (ulonglong)_Y) != 0);
} else {
    iVar3 = 2;
}
```
你不用去开计算器，我帮你算过了。在这里，`iVar3 = 1` 时表示奇数，`iVar3 = 2` 时表示偶数。

在 `if (((ulonglong)_X & 0x8000000000000000) != 0)` 这个代码块执行完毕后，几个变量的状态如下：

`_X`: 原始输入，值仍为 -1.0。

`iVar3`: 值为 2，代表 `_Y` 是一个偶数。

`lVar12`: 符号标志位，由于 `iVar3 != 1`，它被正确地清零，代表最终结果应该是正数。

`dVar13`: 临时变量，在 `dVar13 = ABS(_X);` 这一行，它的值已经从 -1.0 变成了 1.0。

问题出现在 137到 142 也就是下面几行中：
```c
}
if (_Y == 1.0) {
    return _X;
}
if (dVar13 == 1.0) {
    return _X;
}
```

不难看出，这里有一个逻辑错误。由于 `dVar13` 在前面的代码中已经被设置为 1.0，而 `_Y` 是 2.0，因此 `dVar13 == 1.0` 的判断为真，导致函数直接返回了 `_X` 的值 -1.0，而不是正确的结果 1.0。因此，当 `_Y` 为偶数时，底数为 -1 的情况会导致错误的结果。

== 为什么正式版中没有这个问题？

这里给出正式版逆向 dll 的代码：https://gist.github.com/purofle/84ee8ef5c7f46a143aa3781eea01471b

在正式版的 191 行中，abs 计算后有这么一段判断：
```c
if ((uVar8 & 0x7ff) - 0x3be < 0x80) {
    if (uVar3 == 0) {
        dVar13 = (double)((longlong)ABS(_X * 4503599627370496.0) + 0xfcc0000000000000);
    }
    goto LAB_18005f8d9;
    }
```
这里的 `uVar8` 等价于 Insider 系统中的 `uVar9`，计算方法也是一样的：
```c
uVar2 = (uint)((ulonglong)_Y >> 0x20);
uVar8 = uVar2 >> 0x14;
```

在正式版的系统中，在获得正确的结果符号位后，直接 goto 到了 `LAB_18005f8d9`，跳转到了正常计算的分支，而 Insider 系统中则没有这个跳转，导致了错误的结果。
