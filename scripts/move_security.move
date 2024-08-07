module move_security::Movement {
    use std::vector;
    use std::option;

    // 자산 구조체 정의
    struct Asset has key, store, drop {
        id: u64,
        owner: address,
        value: u64,
    }

    // 사용자의 자산을 관리하는 테이블
    struct AssetTable has key, store {
        assets: vector::Vector<Asset>,
    }

    // AssetTable을 초기화하는 함수
    public fun initialize(): AssetTable {
        AssetTable { assets: vector::empty<Asset>() }
    }

    // 새로운 자산을 생성하여 벡터에 추가하는 함수
    public fun create_asset(asset_table: &mut AssetTable, owner: address, asset_id: u64, value: u64) {
        let new_asset = Asset { id: asset_id, owner, value };
        vector::push_back(&mut asset_table.assets, new_asset);
    }

        // 자산의 소유권을 확인하는 함수
    public fun verify_ownership(asset_table: &AssetTable, asset_id: u64, owner: address): bool {
        let idx = find_asset_index(asset_table, asset_id);
        idx.is_some() && vector::borrow(&asset_table.assets, idx.unwrap()).owner == owner
    }


}
