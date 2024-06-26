# 智能合约安全问题整理

1. [重入攻击（Reentrancy Attack）](#1-重入攻击reentrancy-attack)
2. [抢先交易攻击（Front-Running Attack）](#2-抢先交易攻击front-running-attack)
3. [可预测随机数攻击（Predictable Random Number Attack）](#3-可预测随机数攻击predictable-random-number-attack)
4. [权限控制问题（Access Control Issues）](#4-权限控制问题access-control-issues)
5. [短地址攻击（Short Address Attack）](#5-短地址攻击short-address-attack)
6. [整数溢出和下溢（Integer Overflow and Underflow）](#6-整数溢出和下溢integer-overflow-and-underflow)

## 1. 重入攻击（Reentrancy Attack）

智能合约的重入攻击是攻击者通过反复调用合约函数，利用合约在更新状态前进行外部调用的漏洞，非法获取资金或进行其他操作。

**攻击案例**：在2016年，"The DAO"智能合约遭到重入攻击，攻击者利用合约中的漏洞反复调用withdraw函数，最终盗取了约360万个以太币。该事件导致了以太坊区块链的硬分叉，形成了以太坊（ETH）和以太坊经典（ETC）两条链。

#### a. 执行控制权转移：重入攻击发生在外部调用时的原因

因为，外部调用，会让当前合约A失去执行控制权，让外部合约B获得执行控制权。获得执行权控制后，外部合约B就可以做坏事。

- 当合约A调用合约B的函数时，例如合约B地址发送以太币，这个调用实际上是一个外部调用。
- 外部合约B（或地址）在接收到调用时，获得了执行控制权。此时，外部合约B可以执行它自己的代码。
- 如果外部合约B在处理被调逻辑时，再次调用了原始合约A的函数，而这个函数在上次调用中还未完成之前的**状态更新**操作，就会导致重入攻击。

代码详解：[重入攻击代码说明](./readmes/1_重入攻击代码说明.md)

#### b. EVM的单线程模型：合约控制权转移的原因

EVM是单线程执行模型，该模型决定了智能合约的执行控制权需要在EVM内发生转移。

- **调用栈**：合约不管是内部调用还是外部调用，都会产生一个调用栈。每次调用都会在调用栈的基础上新增一层，直达达到最大的调用深度。
- **内部调用**：合约内部函数之间的调用，也会产生调用栈，但执行控制权不会离开合约。
- **外部调用**：一个合约调用另一个合约的函数，或者通过call、delegatecall、staticcall等方法进行调用，会把执行控制权转移给外部合约。

#### c. 重入攻击解决方案

使用OpenZeppelin的ReentrancyGuard形成互斥锁，[重入攻击解决办法代码说明](./readmes/2_重入攻击解决办法.md) 

## 2. 抢先交易攻击（Front-running Attack）

攻击者利用对未确认交易的提前知晓，通过抢先插入的交易来获利。

**攻击案例**：在PEPE Token网络上，攻击者利用三明治攻击（抢先交易攻击的复杂形式）机器人对所有PEPE买入交易进行抢先交易。攻击者通过首先发起大额买单，推动代币价格上升，然后在受害者的买单执行之前再进行卖单，从中获利。仅在24小时内，攻击者就通过这种方法赚取了超过140万美元的利润。

#### a. 交易池：抢先交易攻击者如何监听未确认交易？

以太坊的交易池是一个临时存储区域，用于存储所有未被矿工打包进区块的交易。

- **临时存储**：交易池存储所有已签名并广播到网络的交易，这些交易尚未被矿工验证和打包到区块中。
- **交易传播**：当用户发送一笔交易时，交易先被存到本地节点的交易池，然后本地节点会广播这笔交易给其他节点。
- **排序和优先级**：交易池中的交易，按照Gas费进行排序。矿工为了赚钱，会优先处理Gas费高的交易。
- **交易处理**：矿工从交易池中选择交易池打包进区块，一旦交易被验证和打包进区块，就从交易池删除。

除了运行区块链全节点能监听交易池外，如今也有很多平台和工具能监听交易池。

#### b. 抢先交易者如何识别获利机会？

- **三明治攻击获利**：例如，抢先交易攻击者监听到，用户A即将在去中心化交易所大量买入代币X，用户A的行为势必会推高代币X的价格。那么，攻击者可以先以低价买入代币X，等用户A的交易推高价格后，再卖出代币X获利。这就是抢先交易者的获利机会。

瞄准了获利机会后，下一步就是实现在用户A前面抢先买入代币X。

#### c. 抢先交易者如何保证自己的交易优先执行？

一个区块中交易的执行顺序，是由矿工决定的。所以抢先交易者想让自己的交易先被执行，那就得贿赂矿工了。

抢先交易者可以做以下事情贿赂矿工：

- **提高Gas费**：矿工会优先验证和打包交易池中Gas费高的交易。但这种做法有个问题，这个抢先交易者的行为，同样也会被其他抢先交易者检测到。
- **利用矿工可提取价值（MEV）平台**：抢先交易者利用MEV平台，直接把交易发给矿工，而不通过交易池。这既确保交易被优先处理，又避免被其他抢先交易者监听。
- **交易捆绑贿赂费用**：抢先交易者把多笔交易捆绑成交易包，交易包中有一笔交易是直接支付给矿工的贿赂费。

#### d. 抢先交易攻击解决方案

通过提交-揭示机制、设置滑点保护、增强隐私保护（如零知识证明）等方案来解决。

## 3. 可预测随机数攻击（Predictable Random Number Attack）

如果智能合约只是使用链上公开的数据（例如区块哈希、时间戳、区块号等）来生成随机数，那么随机数是可被预测的。攻击者提前预测随机数结果，这会让游戏、彩票、抽奖等依赖随机数的DApp应用受攻击。

**攻击案例**：2018年，在Fomo3D游戏中，攻击者通过操控区块时间戳，预测并操纵随机数生成过程，赢得大奖。

可预测随机数攻击的解决办法：

- **使用链下随机数**：目前很多预言机平台提供链下不可预测的随机数生成，我在[Roulette-dApp](https://github.com/chen-qr/Roulette-dApp)项目中有使用。但是，链下随机数需要信任一个中心化的第三方，这本身也是风险。
- **多方生成随机数**：多个参与方来提交多个生成随机数的种子，减少单一方控制随机数的风险。方案的好处是去中心化，难预测，问题是系统实现比较复杂。
- **延迟随机数生成**：在一个区块中先提交请求，未来的区块再生成随机数，攻击者很难预测未来区块的状态。这种方案虽然随机数难预测，但是随机数还是依靠区块数据生成，本身也没有那么随机。

## 4. 权限控制问题（Access Control Issues）

合约中重要敏感的函数，没有设置权限验证，被攻击者调用。

**攻击案例**：在2017年，Parity钱包的多重签名合约存在一个严重漏洞，导致攻击者能够获取合约的管理员权限，并将多个钱包的资金转移到自己的账户中，损失高达30万个以太币。

**权限控制解决方案**：使用权限控制模式，如OpenZeppelin的Ownable协议或AccessControl协议。其中，Ownable协议适合简单权限控制，AccessControl适合多角色和权限的管理。

## 5. 短地址攻击（Short Address Attack）

EVM对于不完整的地址，会在地址尾部自动补0，所以攻击者会故意构造不完整的缩短地址，传入合约函数，让合约处理错误的地址。

**攻击案例**：在2017年，Golem Project团队发现了一个安全漏洞，影响了包括Poloniex在内的一些交易所。当这些交易所处理ERC20代币交易时，未对账户地址长度进行正确的输入验证，导致攻击者能够利用短地址攻击转移更多的代币。

**短地址攻击解决方案**: 使用OpenZeppelin的RC20标准提供的地址操作函数（例如转账）。

## 6. 整数溢出和下溢（Integer Overflow and Underflow）

当算术操作超过数据类型的最大或最小值时，会导致意外的行为。

**攻击案例**：在2018年，BEC美蜜合约出现整数乘法溢出漏洞，攻击者可以通过代币合约的批量转账方法无限生成代币，BEC价值瞬间归零。

解决方案：使用SafeMath库来进行安全的算术操作。
