# SmartContractSafetyLists
智能合约安全问题整理


## 1. 重入攻击（Reentrancy Attack）

智能合约的重入攻击是攻击者通过反复调用合约函数，利用合约在更新状态前进行外部调用的漏洞，非法获取资金或进行其他操作。

#### a. 外部调用：为什么重入攻击发生在外部调用时？

因为，外部调用，会让当前合约A失去执行权，让外部合约B获得执行权。获得执行权后外部合约B就可以做坏事。

- 当合约A调用合约B的函数时，例如发送以太币给一个外部地址，这个调用实际上是一个外部调用。
- 外部合约B（或地址）在接收到调用时，获得了执行控制权。此时，外部合约B可以执行它自己的代码。
- 如果外部合约B的代码在处理外部调用的过程中，再次调用了原始合约A的一个函数，而这个函数可能还未完成之前的**状态更新**操作，就会导致重入攻击。

#### b. 执行控制权转移：滋生重入攻击的EVM特性

EVM是**单线程**执行模型，该模型决定了智能合约的执行控制权需要在EVM内发生转移。

- 调用栈：合约不管是内部调用还是外部调用，都会产生一个调用栈。每次调用都会在调用栈的基础上新增一层，直达达到最大的调用深度。
- 内部调用：合约内部函数之间的调用，也会产生调用栈，但执行控制权不会离开合约。
- 外部调用：一个合约调用另一个合约的函数，或者通过call、delegatecall、staticcall等方法进行调用，会把执行控制权转移给外部合约。

#### c. 重入攻击解决方案

使用OpenZeppelin的ReentrancyGuard形成互斥锁，[查看详解](./readmes/1_重入攻击解决办法.md) 

## 2. 前端交易攻击（Front-running Attack）

攻击者利用对未确认交易的提前知晓，通过插入的交易来获利。

#### a. 交易池：前端交易攻击者如何监听未确认交易？

以太坊的交易池是一个临时存储区域，用于存储所有未被矿工打包进区块的交易。

- **临时存储**：交易池存储所有已签名并广播到网络的交易，这些交易尚未被矿工验证和打包到区块中。
- **交易传播**：当用户发送一笔交易时，交易先被存到本地节点的交易池，然后本地节点会广播这笔交易给其他节点。
- **排序和优先级**：交易池中的交易，按照Gas费进行排序。矿工为了赚钱，会优先处理Gas费高的交易。
- **交易处理**：矿工从交易池中选择交易池打包进区块，一旦交易被验证和打包进区块，就从交易池删除。

除了运行区块链全节点能监听交易池外，如今也有很多平台和工具能监听交易池。

#### b. 抢先交易：前端交易者如何识别获利机会？

例如，前端交易攻击者监听到，用户A即将在去中心化交易所大量买入代币X，用户A的行为势必会推高代币X的价格。

那么，攻击者可以先以低价买入代币X，等用户A的交易推高价格后，再卖出代币X获利。这就是前端交易者的获利机会。

#### c. 贿赂矿工：前端交易者如何保证自己的交易优先执行？

前端交易者有需要方式保证自己的交易被优先处理：

- 提高Gas费：矿工会优先验证和打包交易池中Gas费高的交易。但这种方式有个问题，这个前端交易者的行为，同样也会被其他前端交易者检测到。
- 利用矿工可提取价值（MEV）平台：前端交易者利用MEV平台，直接把交易发给矿工，而不通过交易池。这确保交易被优先处理，还避免被其他前端交易者监听。
- 交易捆绑贿赂费用：前端交易者把多笔交易捆绑成交易包，交易包中有一笔交易是直接支付给矿工的贿赂费。

#### d. 前端交易攻击解决方案

通过提交-揭示机制、设置滑点保护、增强隐私保护（如零知识证明）等方案来解决。

## 3. 交易顺序依赖（Transaction Order Dependence, TOD）

区块链上交易是顺序执行的，而交易顺序是由矿工决定的。攻击者可以故意操控交易顺序来影响合约的执行结果。


## 4. 竞态条件（Race Conditions）

## 5. 可预测的随机数（Predictable Randomness）

## 6. 权限控制问题（Access Control Issues）

合约中重要敏感的函数，没有设置权限验证，被攻击者调用。

**权限控制解决方案**：使用权限控制模式，如OpenZeppelin的Ownable协议或AccessControl协议。其中，Ownable协议适合简单权限控制，AccessControl适合多角色和权限的管理。

## 7. 短地址攻击（Short Address Attack）

EVM对于不完整的地址，会在地址尾部自动补0，所以攻击者会故意构造不完整的缩短地址，传入合约函数，让合约处理错误的地址。

**短地址攻击解决方案**: 使用OpenZeppelin的RC20标准提供的地址操作函数（例如转账）。

## 8. 整数溢出和下溢（Integer Overflow and Underflow）

当算术操作超过数据类型的最大或最小值时，会导致意外的行为。

解决方案：使用SafeMath库来进行安全的算术操作。

## 9. 未处理的异常