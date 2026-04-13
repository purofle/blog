#import "@preview/shiroa:0.1.0": *
#import "@preview/typst-apollo:0.1.0": pages
#import pages: *
#import "@preview/shiroa:0.1.0": get-page-width, is-pdf-target, is-web-target, plain-text, target

#import "@preview/unequivocal-ams:0.1.0": proof, theorem

#show: project.with(
  title: "今日校园登录请求逆向分析",
  authors: (
    (
      name: "purofle",
      email: "purofle@gmail.com",
    ),
  ),
)

#set par(justify: true)

== 准备阶段
这里本来是准备直接对 Android 版进行逆向，但是 Android 版存在 SSL Pinning，导致无法直接抓包分析。通过拆包后发现 Android 版使用了爱加密企业版，其 so 二进制采用了爱加密 LLVM 进行加固，同时爱加密企业壳还存在 frida 反调试，逆向难度较大，所以这里改为对 iOS 版进行逆向分析。iOS 版没有 SSL Pinning，且不存在加固，所以相对来说更容易分析。

今日校园是直接从 macOS 的 App Store 里下载的，这里采用的是 Surge 进行抓包。

== 初步抓包分析
抓包分析发现，首个请求为 `https://mobile.campushoy.com/app/auth/dynamic/secret/getSecretKey/v-920`，观察请求发现 Header 中存在一个名为 CpdailyInfo，同样为加密后的 base64 字符串。之后通过 endpoint 猜测是获取动态密钥的接口，响应中 data 为一个 128 长度的 base64 字符串，猜测为 AES 加密的密钥。

之后就发起了获取学校信息的请求： `https://mobile.campushoy.com/v6/config/guest/tenant/info/v-8222?a=学校id&b=first_v4`，这个请求返回的 data 很大，应该包括学校的各种配置，依旧是加密的。

接下来 App 端进入学校的 oauth2 流程，内置的 WebKit Networking 打开了 `https://authserver.yourschool.edu.cn/authserver/mobile/auth?appId=xxxxxx`，在输入账号密码登录后经过两次 302 跳转最终会到达 `http://authserver.yourschool.edu.cn/authserver/mobile/default.html#mobile_token=xxx/xxx/xxx`，之后 App 就进入到了主界面，猜测 mobile_token 就是登录成功后返回的 token。

== 逆向分析
=== 获取 CpdailyInfo
对 iOS ipa 进行砸壳，从 ipa 中提取出 CampusNext，拽进 IDA 进行分析。在函数列表中可以直接找到 CpdailyInfo 的几个方法，同时还可确定 CpdailyInfo 编译后的类名为 `_TtC10CampusNext11CpdailyInfo`，这里通过查看 `_OBJC_CLASS_$__TtC10CampusNext11CpdailyInfo __objc2_class` 的 xrefs 可以找到方法 `-[CpdailyNetworkManager setupRequestHeader:timeoutInterval:]`，通过名字猜测作用是设置请求头。

其中注意到这么一段代码：
```m
v38 = objc_retainAutoreleasedReturnValue(+[PublicMethodsgetDeviceInfo](&OBJC_CLASS___PublicMethods, "getDeviceInfo"));
v39 = objc_retainAutoreleasedReturnValue(objc_msgSend(v38,"mj_JSONString"));
v40 = objc_retainAutoreleasedReturnValue(+[DESCrypt encrypt:](OBJC_CLASS___DESCrypt, "encrypt:", v39));
objc_release(v39);
v41 = objc_retainAutoreleasedReturnValue(-[AFHTTPSessionManager requestSerializer](v6, "requestSerializer"));
-[AFURLRequestSerialization setValue:forHTTPHeaderField:](
  v41,
  "setValue:forHTTPHeaderField:",
  v40,
  CFSTR("CpdailyInfo"));
```
发现调用了 `+[DESCrypt encrypt:]` 方法对 `getDeviceInfo` 的结果进行加密后设置到 CpdailyInfo 这个 Header 中，于是我们查看 `+[DESCrypt encrypt:]`，发现直接调用了 `+[DESCrypt encrypt:keyVersion:]`，而 `+[DESCrypt encrypt:keyVersion:]` 的实现中调用了 `CCCrypt` 进行加密：
```m
id __cdecl +[DESCrypt encrypt:keyVersion:](id a1, SEL a2, id a3, signed __int64 a4)
{
  id v6; // x21
  void *v7; // x19
  const void *v8; // x20
  void *v9; // x22
  CCCryptorStatus v10; // w0
  id v11; // x20
  NSData *v12; // x21
  size_t dataOutMoved; // [xsp+18h] [xbp-C48h] BYREF
  __int64 iv; // [xsp+20h] [xbp-C40h] BYREF
  _BYTE dataOut[3072]; // [xsp+28h] [xbp-C38h] BYREF

  v6 = objc_retain(a3);
  v7 = objc_retainAutoreleasedReturnValue(objc_msgSend(a1, "getCryptKeyByVersion:", a4));
  v8 = objc_msgSend(objc_retainAutorelease(v6), "UTF8String");
  v9 = objc_msgSend(v6, "length");
  objc_release(v6);
  dataOut[0] = 0;
  dataOutMoved = 0;
  iv = 0x807060504030201LL;
  v10 = CCCrypt(
          0,
          1u,
          1u,
          objc_msgSend(objc_retainAutorelease(v7), "UTF8String"),
          8u,
          &iv,
          v8,
          (size_t)v9,
          dataOut,
          0xC00u,
          &dataOutMoved);
  v11 = nullptr;
  if ( !v10 )
  {
    v12 = objc_retainAutoreleasedReturnValue(+[NSData dataWithBytes:length:](&OBJC_CLASS___NSData, "dataWithBytes:length:", dataOut, dataOutMoved));
    v11 = objc_retainAutoreleasedReturnValue(+[DESCrypt encode:](&OBJC_CLASS___DESCrypt, "encode:", v12));
    objc_release(v12);
  }
  objc_release(v7);
  return objc_autoreleaseReturnValue(v11);
}
```

通过查看 CCCrypt 方法参数可知，加密算法为 DES，模式为 ECB，填充方式为 PKCS7，密钥通过 `+[DESCrypt getCryptKeyByVersion:]` 获取。