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
发现调用了 `+[DESCrypt encrypt:]` 方法对 `getDeviceInfo` 的结果转为 json进行加密后设置到 CpdailyInfo 这个 Header 中，于是我们查看 `+[DESCrypt encrypt:]`，发现直接调用了 `+[DESCrypt encrypt:keyVersion:]`，而 `+[DESCrypt encrypt:keyVersion:]` 的实现中调用了 `CCCrypt` 进行加密：
```m
v6 = objc_retain(a3);
v7 = objc_retainAutoreleasedReturnValue(objc_msgSend(a1,"getCryptKeyByVersion:", a4));
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
  v12 = objc_retainAutoreleasedReturnValue(+[NSDatadataWithBytes:length:](&OBJC_CLASS___NSData,"dataWithBytes:length:", dataOut, dataOutMoved));
  v11 = objc_retainAutoreleasedReturnValue(+[DESCrypt encode:](OBJC_CLASS___DESCrypt, "encode:", v12));
  objc_release(v12);
}
objc_release(v7);
return objc_autoreleaseReturnValue(v11);
}
```

通过查看 CCCrypt 方法参数可知，加密算法为 DES，模式为 ECB，填充方式为 PKCS7，密钥通过 `+[DESCrypt getCryptKeyByVersion:]` 获取，代码如下：
```m
id __cdecl +[DESCrypt getCryptKeyByVersion:](id a1, SEL a2, signed __int64 a3)
{
  if ( (unsigned __int64)a3 > 4 )
    return &stru_104B440F8;
  else
    return off_104A06EC0[a3];
}

__const:0000000104A06EC0 off_104A06EC0 DCQ cfstr_Xce927 ; "XCE927=="
__const:0000000104A06EC8 DCQ cfstr_St83Xv    ; "ST83=@XV"
__const:0000000104A06ED0 DCQ cfstr_QtzA54    ; "QTZ&A@54"
__const:0000000104A06ED8 DCQ cfstr_Hyd6ys4v  ; "hYd6YS4V"
__const:0000000104A06EE0 DCQ cfstr_B3l26xnl  ; "b3L26XNL"
```

`+[DESCrypt encrypt:]` 中传入的 keyVersion 是 0，所以最终密钥为 `XCE927==`。

`+[PublicMethods getDeviceInfo]` 中构建了一个包含设备信息的字典，大概包含以下信息：
```json
{
    "deviceId":"替换为你的 deviceID",
    "systemName":"iPadOS",
    "appVersion":"9.9.7",
    "model":"iPad8,6",
    "lon":0,
    "cpdailyVersion":"9.9.7",
    "systemVersion":"26.3",
    "lat":0
}
```
对这个 Json 使用刚才的 DES 加密后进行 Base64 编码，就得到了 CpdailyInfo 这个 Header 的值。

=== 获取动态密钥

我们还需要处理 `getSecretKey` 请求中的另外两个参数，一个 `p` 和一个 `s`。

这个请求的构造在 `-[LoginService getSecretKey:]` 方法中可以找到：

p 参数的构造代码如下：
```m
v6 = objc_retainAutoreleasedReturnValue(+[NSString getCNUUID](OBJC_CLASS___NSString, "getCNUUID"));
v7 = objc_retainAutoreleasedReturnValue(+[CryptUtil secretVersion(&OBJC_CLASS___CryptUtil, "secretVersion"));
v8 = objc_retainAutoreleasedReturnValue(+[NSStringstringWithFormat:](&OBJC_CLASS___NSString, "stringWithFormat:",CFSTR("%@|%@"), v6, v7));
objc_release(v7);
objc_release(v6);
v9 = (__CFString *)objc_retainAutoreleasedReturnValue(+[CryptUtil rsaEncrypt:](&OBJC_CLASS___CryptUtil, "rsaEncrypt:", v8));
```

`p` 参数由两部分构成，前面为随机生成的 UUID，后面为 secretVersion, secretVersion 从 `+[ConstantKeyCrypt localSecretVersion:]` 方法获得，我这里的值为 `first_v4`，中间使用 `|` 分割。

`+[CryptUtil rsaEncrypt:]` 在判断是否处于开发版后调用了 `-[CNRSACrypt rsaEncryptLocalString:isDevelopment:]`，这个函数从 `localBundle` 里加载了一个名为 `dis_public_key.der` 的公钥文件，对上面构造的字符串进行 RSA 加密，最后进行 Base64 编码返回。

`s` 为前面参数 `p` 的签名，通过 MD5 加盐的方式计算。salt 的值可以直接通过 `+[EncryptConstant localSalt]` 的汇编中拿到，是一个固定值，我这里的值为 `2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824`，拼接成 刚才算出的密文&盐值，对其进行一次 MD5 哈希即可。

接下来对返回值进行解密，通过查找 `-[LoginService getSecretKey:]` 的 xrefs 可以找到 `-[LoginManager syncLoginSecret:]`，部分代码如下：
```m
v5 = objc_opt_new(&OBJC_CLASS___LoginService);
v6[0] = _NSConcreteStackBlock;
v6[1] = 3254779904LL;
v6[2] = sub_10034269C;
v6[3] = &unk_104975AE8;
v6[4] = self;
v7 = objc_retain(v4);
-[LoginService getSecretKey:](v5, "getSecretKey:", v6);
```

其中第三个参数 `sub_10034269C` 是一个回调函数，写的很麻烦，但是我们只需要注意其中几行代码：
```m
v10 = objc_retainAutoreleasedReturnValue(objc_msgSend(v5, "data"));
v11 = objc_retainAutoreleasedReturnValue(+[CryptUtil rsaDecrypt:](&OBJC_CLASS___CryptUtil, "rsaDecrypt:", v10));
```

发现这里调用了 `+[CryptUtil rsaDecrypt:]` 方法对返回的 data 进行 RSA 解密，`+[CryptUtil rsaDecrypt:]` 类似前面的 `+[CryptUtil rsaEncrypt:]`，同样判断是否处于开发版后调用了 `-[CNRSACrypt rsaDecryptLocalString:isDevelopment:]`，不同的是 `-[CNRSACrypt rsaDecryptServiceString:isDevelopment:]` 加载的是 `dis_private_key.p12` 的私钥文件。有了私钥还需要密码，密码就在下面的 `+[ConstantKeyCrypt disp12Password]` 方法中获取，查看对应的汇编，比较重要的部分有下面几句：
```yasm
var_s0 = 0
var_8 = -8
SUB       SP, SP, #0x20 ; 开辟栈空间 大小为 0x20
STP       X29, X30, [SP,#0x10+var_s0] ; 保存 X29 和 X30
ADD       X29, SP, #0x10 ; 设置新的栈帧
MOV       W8, #0xBB8A8398
STUR      W8, [SP,#0x10+var_8+3] ; 存储 0xBB8A8398 到栈的 [X29-8] 的位置
MOV       W8, #0x989DC8E9
STR       W8, [SP,#0x10+var_8] ; 存储 0x989DC8E9 到栈的 [X29-5] 的位置
ADD       X8, SP, #0x10+var_8  ; X8 指向栈的 [X29-8] 的位置, 作为 buffer 传入下面的循环
loc_101065C84:
LDRB      W9, [X8] ; 把 X8 指向的地址的值加载到 W9 中
EOR       W10, W9, #0xBBBBBBBB ; W10 = W9 XOR 0xBBBBBBBB
STRB      W10, [X8],#1 ; 把 W10 存储回 X8 指向的地址，并且 X8 加 1
CMP       W9, #0xBB ; 比较 W9 和 0xBB 的值
B.NE      loc_101065C84 ; 如果 W9 不等于 0xBB 则继续循环
```
这里把 0xBB8A8398 存储到了栈的 X29-8 的位置，把 0x989DC8E9 存储到了栈的 X29 的位置。完成后进入循环，当完成循环后，最后一个 0xBB 被异或掉了，`0xBB xor 0xBB = 0`，所以循环结束后栈的 [X29-8] 的位置存储的就是 `0x989DC8E9`。我们可以编写一段 Python 代码来计算：
```python
v1 = 0x989DC8E9
v2 = 0xBB8A8398

buf = bytearray(8)
buf[0:4] = v1.to_bytes(4, 'little') # [X29-5]
buf[3:7] = v2.to_bytes(4, 'little') # [X29-8]
out = bytearray()
for b in buf:
    out.append(b ^ 0xBB)
    if b == 0xBB:
        break
print(out.rstrip(b'\x00').decode(errors='replace'))
```

最终得到密码为 `Rs&#81`。

提取 App 中的 dis_private_key.p12，使用上面计算出的私钥密码，解密后可得到下面这样的明文：
```
d467f9a1-199f-4c1b-a942-422605aec09e|Yn8g6T5R|7hriwfra
```

在软件中使用下面的结构体储存从服务端获取的 SecretKey:
```
struct _TtC7CNCrypt13ServiceSecret // sizeof=0x38
{
    NSObject super;
    unsigned __int8 randomString[16];
    unsigned __int8 cpdailySecret[16];
    unsigned __int8 catSecret[16];
};
```
其中内容使用 | 分割。

=== 计算请求中的 AES 密钥

在请求中，请求参数会通过 `+[CryptUtil aesEncrypt:]` 方法进行加密，回应中 data 会通过 `+[CryptUtil aesDecrypt:]` 方法进行解密。

为了方便，下面所说的 AES 都为 AES-CBC 模式，填充方式为 PKCS7。

这两个方法都通过 `+[CryptUtil campushoySecret]` 获取动态的 AES 密钥，`+[CryptUtil campushoySecret]` 通过调用 `sub_101068EC8` 获取 AES 密钥，`sub_101068EC8` 的代码很长，我们同样只看关键部分：
```m
v13 = (void *)swift_getInitializedObjCClass(&OBJC_CLASS___ConstantKeyCrypt);
v14 = &selRef_localDevCpdailySecret;
if ( !v12 )
    v14 = &selRef_localDisCpdailySecret;
v15 = objc_retainAutoreleasedReturnValue(objc_msgSend(v13, *v14));
```
这里按环境选出 localDisCpdailySecret，localDisCpdailySecret 与上面的 `disp12Password` 实现的混淆方式大概一样，最终得到的值为 `f9akfyUe`。

这里因为原始的是 swift 代码，编译后不好理解。我让 LLM 代码改写成了 swift 版本：
```swift
func sub_1010684C4(_ a1: String, _ a3: String) -> String {
    var s = a1
    s.append(a3)

    let chars = Array(s)

    var v19: [Character] = []   // 偶数位
    var v20: [Character] = []   // 奇数位

    for (v22, ch) in chars.enumerated() {
        if (v22 & 1) == 0 {
            v19.append(ch)
        } else {
            v20.append(ch)
        }
    }

    let v33 = String(v19)
    let v34 = String(v20)

    var tmp = v33
    tmp.append(v34)

    return v33
}
```

这个函数的作用是把输入字符串的偶数位和奇数位分开，分别组成两个字符串，最后把偶数位的字符串放在前面，奇数位的字符串放在后面，组合成一个新的字符串返回，返回的新字符串就是 AES 加密解密的最终密钥。

=== 最终登录流程
最后的登录流程在 `-[LoginService notCloudLogin:tenantId:block:]` 中实现，在这个方法中构造了一个这么一个 json：
```json
{"d": 上面拿的mobile_token, "c": tenantId}
```
然后通过 `-[CpdailyNetworkManager net_CryptPOST:parameters:decryptRsp:block:]` 发送请求前，会对这个 json 通过 `+[CpdailyNetworkManager encryptParams:]` 方法进行 AES 加密，AES 密钥通过上面提到的 `sub_101068EC8` 方法计算得到，加密后构成了一个新的 json：
```json
{"a": 加密后的字符串, "b": "secretVersion"}
```
`secretVersion` 依旧是 `first_v4`，服务端拿到这个请求后会进行 AES 解密，解密后就得到了上面那个 json，拿到 json 中的 mobile_token 和 tenantId 就可以完成登录了。