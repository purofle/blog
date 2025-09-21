#import "@preview/shiroa:0.1.0": *
#import "@preview/typst-apollo:0.1.0": pages
#import pages: *
#import "@preview/shiroa:0.1.0": get-page-width, target, is-web-target, is-pdf-target, plain-text

#import "@preview/unequivocal-ams:0.1.0": theorem, proof

#show strong: content => {
  show regex("\p{Hani}"): it => box(place(text("·", size: 0.8em), dx: 0.1em, dy: 0.75em) + it)
  content.body
}

#show: project.with(
  title: "从零学习密码学-Keccak 研究",
  authors: (
    (
      name: "purofle",
      email: "purofle@gmail.com",
    ),
  ),
)

#set par(justify: true)
#set quote(block: true)

// = 从零学习密码学-Keccak研究

== 海绵函数

#quote(attribution: "维基百科")[
  在密码学，海绵函数（sponge function）或者海绵建构（sponge construction）是一种算法。它使用有限的状态，接收任何长度的输入位元流，然后可以满足任何长度的输出。海绵函数可以在理论上面或者实做上面应用，用来架构或者实做密码学的原始函数，像是加密散列函数（cryptographic hash，参考散列函数）等等.
]

看起来有点抽象，我们一点点来理解.

海绵函数有两个阶段，吸收（Absorbing）跟挤出（Squeezing），这也是海绵函数这个名字的由来.

海绵函数有以下几个参数：
- 状态 $S$，以及状态总长 $b$. 这个状态会被分为两个部分，内部部分和外部部分. 内部部分的长度为 $c$，外部部分的长度为 $r$.
- 转换率 $r$，因为转换率 $r$ 是外部状态的长度，所以 $r=b-c$.

在吸收阶段，状态 $S$ 会被初始化为0. 然后把输入的东西使用特定算法进行填充，然后被分割成有 $r$ 长度的块. 这些块会与外部部分进行异或运算，然后使用转换函数 $f$ 进行处理. 这个过程会持续到所有的输入都被处理完为止.

在挤出阶段，长度为 $r$ 的外部部分会被输出. 如果输出的长度大于 $r$，就会使用转换函数 $f$ 进行处理，然后再输出 $r$ 的长度. 这个过程同样会持续到所有的输出都被处理完为止#super[@b-2011].

== Keccak基础

Keccak 其实就是一系列海绵函数. 它使用一个叫做multi-rate的填充方式，使用公式表示为 $"pad10"*1$，意思是输出一个1，然后后面接上多个0，直到长度为 $r-1$. 它的计算方法如下：

输入一个正整数 $x$，一个非负整数 $m$，输出一个串 $P$ 使得 $m+"len"(P)$ 是 $x$ 的正整数倍#super[@nist-author-2015].

步骤：
#block[
  1. $j=(-m-2) mod x$
2. $P=1||0^j||1$
]

Keccak的置换函数使用 $"KECCAK"-p[b, n_r]$ 表示，它的总长是 $b$, $n_r$ 代表轮数.

在接下来我们还会出现两个参数，$w$ 和 $ell$, 其中 $w = b/25$，$ell=log_2(b/25)$.

Keccak的状态 $S$ 是一个三维数组，可表示为：
$ {(x,y,z) mid(|) x, y in [0,5), z in [0, w) } $

Keccak 的核心公式其实就是：
$ "Rnd"(A,i_r)=iota(chi(pi(rho(theta(A)))), i_r) $

看起来有点复杂，我们一点一点理解. 这里的 $A$ 代表状态，$i_r$ 代表论数，所以左边的 $"Rnd"(A, i_r)$ 其实就是 $A$ 经过 $i_r$ 次置换后的状态.

接下来我们依次理解右边的一系列函数.

- $theta$：我们计算的第一个函数，它的作用是把状态 $A$ 复杂化. 这个函数的计算方法如下：
#quote[
  对于所有的 $(x,y)$ 对，且 $0<=x<5, 0<=z<w$，我们有
  1. $C'[x, z] = A[x, 0, z] xor A[x, 1, z] xor A[x, 2, z] xor A[x, 3, z] xor A[x, 4, z]$
  2. $D'[x, z] = C'[(x-1) mod 5,z] xor C'[(x+1) mod 5, (z-1) mod w]$
  对于所有的 $(x,y,z)$，且 $0<=x<5, 0<=y<5, 0<=z<w$，我们有
  3. $A'[x,y,z] = A[x,y,z] xor D'[x,z]$
]

不难看出，$theta$ 只进行 $x, z$ 方向上的异或运算.

- $rho$：这个函数的作用是把状态 $A$ 进行旋转，方法如下：
#quote[
  1.对于所有的 $z$，且 $0<=z<w$，我们使 $A'[0,0,z]=A[0,0,z]$
  2. 使$(x,y)=(1,0)$
  3. 对于循环变量$t$，且 $0<=t<24$，我们进行这样的计算：
   - 使$A'[x,y,z]=A[x,y,(z-(t+1)(t+2)/2) mod w]$
   - 使 $(x,y)=(y,(2x+3y) mod 5)$
]

= 剩下的函数可以以此类推，照着文档流程变换即可（其实是懒得写了）

#bibliography("refs.bib")