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