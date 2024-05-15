# SmartContractSafetyLists
智能合约安全问题整理


## 1. 重入攻击

智能合约的重入攻击是攻击者通过反复调用合约函数，利用合约在更新状态前进行外部调用的漏洞，非法获取资金或进行其他操作。

### 外部调用：为什么重入攻击发生在外部调用时？

因为，外部调用，会让当前合约A失去执行权，让外部合约B获得执行权。获得执行权后外部合约B就可以做坏事。

- 当合约A调用合约B的函数时，例如发送以太币给一个外部地址，这个调用实际上是一个外部调用。
- 外部合约B（或地址）在接收到调用时，获得了执行控制权。此时，外部合约B可以执行它自己的代码。
- 如果外部合约B的代码在处理外部调用的过程中，再次调用了原始合约A的一个函数，而这个函数可能还未完成之前的**状态更新**操作，就会导致重入攻击。

### 执行控制权转移：重入攻击的根本原因

EVM是**单线程**执行模型，该模型决定了智能合约的执行控制权需要在EVM内发生转移。

- 调用栈：合约不管是内部调用还是外部调用，都会产生一个调用栈。每次调用都会在调用栈的基础上新增一层，直达达到最大的调用深度。
- 内部调用：合约内部函数之间的调用，也会产生调用栈，但执行控制权不会离开合约。
- 外部调用：一个合约调用另一个合约的函数，或者通过call、delegatecall、staticcall等方法进行调用，会把执行控制权转移给外部合约。

### 避免重入攻击（一）：先更新数据、再外部调用

```solidity
pragma solidity ^0.8.0;

contract SafeContract {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // ✅正确代码：先更新数据、再外部调用
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // 先更新余额
        balances[msg.sender] -= amount;

        // 再发送以太币
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }

    // ❌错误代码：先外部调用、采取更新余额，会被重入攻击，造成余额损失
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // 发送以太币给请求者
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // 更新余额
        balances[msg.sender] -= amount;
    }
}
```

## 2. 短地址攻击

利用以太坊合约中参数解析的漏洞，攻击者通过发送短地址来引起合约解析错误，进而执行恶意行为。

