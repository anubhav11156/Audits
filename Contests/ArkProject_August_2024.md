# ArkProject 
## Contest Summary
- Code under review : [2024-07-ark-project](https://github.com/Cyfrin/2024-07-ark-project)
- nSLOC : 2301
- Rank : 10/81
## Findings Summary
| Severity | Tittle | 
|:----------:|:--------------:|
| High-03 | DoS in white_list_collection() when de-whitelisting L2 collections if more than 2 collections exists in the list|
| High-04 | NFT contract deployed by L1 Bridge cannot be upgraded, nor can its ownership be transferred|
## Findings 
###  [ High-03 ] DoS in white_list_collection() when de-whitelisting L2 collections if more than 2 collections exists in the list
#### Summary

In the L2 `bridge.cairo`, the admin-only function `white_list_collection()` is responsible for both whitelisting and de-whitelisting L2 collections. The bridge manages these collections using a linked-list like data structure. However, a Denial-of-Service (**DoS**) vulnerability occurs when the admin attempts to de-whitelist a collection from the list if there are more than two collections present in the list.

#### Vulnerability Details
In `white_list_collection(collection, enabled)`, the `enabled` flag determines whether the whitelisting or de-whitelisting logic is executed within the function. However, the linked-list implementation for de-whitelisting is flawed. After the first traversal, the logic fails to update the pointer to correctly reference the next collection in the list, leading to an infinite loop and ultimately causing the transaction to be reverted.

[bridge.cairo#L515-L540](https://github.com/ArkProjectNFTs/bridge/blob/main/apps/blockchain/starknet/src/bridge.cairo#L515C1-L540C1)


```
} else { 
    // change head
	if prev == collection {
		let (_, next) = self.white_listed_list.read(prev);
		self.white_listed_list.write(collection, (false, no_value));
		self.white_listed_head.write(next);
		return;
	}
	// removed element from linked list
	loop {
	  let (active, next) = self.white_listed_list.read(prev);
	  if next.is_zero() {
		  // end of list
		  break;
	  }
	  if !active {
		 break;
	  }
	  if next == collection {
		 let (_, target) = self.white_listed_list.read(collection);
		 self.white_listed_list.write(prev, (active, target));
		 break;
	 }
     // @audit >> Missing pointer update
};
self.white_listed_list.write(collection, (false, no_value));
```
Here in `loop`  block, pointer is not being updated i.e missing `prev = next`

**Test :**
```
    #[test]
    fn test_whitelisting_dos() {
        let erc721b_contract_class = declare("erc721_bridgeable");

        let bridge_admin = starknet::contract_address_const::<'starklane'>();
        let bridge_l1 = EthAddress { address: 'starklane_l1' };

        let (bridge_address, _bridge_class) = deploy_starklane(
            bridge_admin, bridge_l1, erc721b_contract_class.class_hash
        );

        let Bridge = IStarklaneDispatcher { contract_address: bridge_address };

        // Admin whitelists 10 collections
        let collections = get_ten_dummy_collections();
        let mut enabled = true;
        let mut i = 0;
        loop {
            if (i == collections.len()) {
                break;
            }
            start_prank(CheatTarget::One(bridge_address), bridge_admin);
            Bridge.white_list_collection(*collections[i], enabled);
            stop_prank(CheatTarget::One(bridge_admin));
            i += 1;
        };
       
        get_collection_and_print(bridge_address);
        println!("{} collections whitelisted",collections.len());
        println!("Attempt to de-whitelist collection_2");
        // Admin tries to de-whitelist a collection ( which is not the head )
        enabled = false;
        start_prank(CheatTarget::One(bridge_address), bridge_admin);
        Bridge.white_list_collection(*collections[2], enabled);
        stop_prank(CheatTarget::One(bridge_admin));

        get_collection_and_print(bridge_address);
    }
```
**Output :**
```
Collected 1 test(s) from starklane package
Running 1 test(s) from src/
Collection_1 :: 2016786432224441567882466605100645
Collection_2 :: 2016786432224441567882466605430639
Collection_3 :: 132172115622261002592745331453250921829
Collection_4 :: 516297326649457041377911450754839922
Collection_5 :: 516297326649457041377911450754446949
Collection_6 :: 2016786432224441567882466605361528
Collection_7 :: 132172115622261002592745331448905885038
Collection_8 :: 132172115622261002592745331388842469492
Collection_9 :: 516297326649457041377911450888662629
Collection_10 :: 2016786432224441567882466605426030
10 collections whitelisted
Attempt to de-whitelist collection_2
[FAIL] starklane::tests::test_whitelisting_poc::testPoc::test_whitelisting_dos

Failure data:
    Got an exception while executing a hint: Hint Error: Error in the called contract (0x0302597adf254f9b9a447a9d6e1ba14ff16f4d7dd01bec7afaa6a4f7e19a61c2):
Error at pc=0:18322:
Could not reach the end of the program. RunResources has no remaining steps.
Cairo traceback (most recent call last):
Unknown location (pc=0:18325)
Unknown location (pc=0:18325)
Unknown location (pc=0:18325)
Unknown location (pc=0:18325)
Unknown location (pc=0:18325)
Unknown location (pc=0:18325)
Unknown location (pc=0:18325)
Unknown location (pc=0:18325)
Unknown location (pc=0:18325)
Unknown location (pc=0:18325)
Unknown location (pc=0:18325)
Unknown location (pc=0:18325)
Unknown location (pc=0:18325)
Unknown location (pc=0:18325)
Unknown location (pc=0:18325)
Unknown location (pc=0:18325)
Unknown location (pc=0:18325)
Unknown location (pc=0:18325)
Unknown location (pc=0:18325)
Unknown location (pc=0:18325)


Tests: 0 passed, 1 failed, 0 skipped, 0 ignored, 0 filtered out

Failures:
    starklane::tests::test_whitelisting_poc::testPoc::test_whitelisting_dos
```
#### Impact

The admin of the L2 bridge will be unable to de-whitelist a collection if more than two collections exist in the list. Given that the bridge serves as a general-purpose NFT bridge between the Ethereum and Starknet ecosystems, it will certainly have more than two whitelisted collections. Additionally, the ArkProject NFT marketplace and order-book product, which acts as a liquidity layer and global infrastructure for digital assets exchange built on Starknet, indirectly uses the bridge (since L1 NFTs need to be bridged to L2 to be available in the marketplace ecosystem). Thus, having more than two whitelisted collections is a given.

If the L2 bridge admin cannot de-whitelist a collection that is malicious, contains vulnerabilty or gets compromised, it could result in asset loss for users. Users depend on the L2 bridge for secure asset transfer, and the bridge is solely responsible for safely transferring assets to L1.

#### Tools Used
Manual review, scarb, starknet-foundry for testing
#### Recommendations

In  `white_list_collection()`, within the de-whitelisting logic block, ensure that the pointer is updated to reference the next collection in the list.
```
} else { 
    // change head
	if prev == collection {
		let (_, next) = self.white_listed_list.read(prev);
		self.white_listed_list.write(collection, (false, no_value));
		self.white_listed_head.write(next);
		return;
	}
	// removed element from linked list
	loop {
	  let (active, next) = self.white_listed_list.read(prev);
	  if next.is_zero() {
		  // end of list
		  break;
	  }
	  if !active {
		 break;
	  }
	  if next == collection {
		 let (_, target) = self.white_listed_list.read(collection);
		 self.white_listed_list.write(prev, (active, target));
		 break;
	 }
     prev = next; // --> Update the pointer here to reference the next collection
};
self.white_listed_list.write(collection, (false, no_value));
```
---
###  [ High-04 ] NFT contract deployed by L1 Bridge cannot be upgraded, nor can its ownership be transferred
#### Summary

ERC721 contract deployed by  L1  `Bridge.sol` when `withdrawTokens()` is called cannot be upgraded or have their ownership transferred.

#### Vulnerability Details

When the ERC721 NFT contract is deployed by the L1 bridge contract, the bridge becomes the owner of the NFT contract. As a result, only the bridge can call `transferOwnership()` and `upgradeTo()` on the NFT contract; otherwise, the transaction will revert. However, the L1 bridge does not expose or implement functions to invoke these transfer and upgrade operations on the NFT contract.
## Impact
* The overall design of ArkProject incorporates upgradeable contracts for both the L1 and L2 sides. However, due to the missing capability in the L1 bridge, the L1 ERC721 NFT contract cannot be upgraded.
* The ownership of the NFT contract can never be changed.
#### Tools Used
Manual 
#### Recommendations
Just as the L2 bridge exposes the `collection_upgrade()` and `collection_transfer_ownership()` functions, which can only be called by the L2 bridge admin, the L1 bridge should similarly implement `collectionUpgrade()` and `collectionTransferOwnership()` functions. These should be callable only by the L1 bridge admin to handle upgrades and ownership transfers of L1 NFT collections.


