module move_security_test::user_registration {
    use std::signer;
    use std::string;
    use aptos_std::table::{Self, Table};
    use aptos_framework::event;

    struct User has key, store {
        address: address,
        username: string::String,
    }

    struct UserRegistry has key, store {
        users: Table<address, User>,
        user_counter: u64,
    }

    const E_NOT_INITIALIZED: u64 = 1;
    const E_USER_ALREADY_EXISTS: u64 = 2;

    #[event]
    struct UserRegistered has store, drop, copy {
        address: address,
        username: string::String,
    }

    public entry fun initialize_user_registry(account: &signer) {
        let user_registry = UserRegistry {
            users: table::new(),
            user_counter: 0
        };
        move_to(account, user_registry);
    }

    public entry fun register_user(account: &signer, username: string::String) acquires UserRegistry {
        let account_address = signer::address_of(account);
        assert!(!exists<UserRegistry>(account_address), E_NOT_INITIALIZED);

        let user_registry = borrow_global_mut<UserRegistry>(account_address);
        let user = User {
            address: account_address,
            username: username,
        };

        assert!(table::contains_key(&user_registry.users, account_address) == false, E_USER_ALREADY_EXISTS);

        table::add(&mut user_registry.users, account_address, user);
        user_registry.user_counter = user_registry.user_counter + 1;

        let user_registered_event = UserRegistered {
            address: account_address,
            username: username,
        };
        event::emit(user_registered_event);
    }

    public fun get_username(account: &signer, user_address: address): string::String acquires UserRegistry {
        let account_address = signer::address_of(account);
        let user_registry = borrow_global<UserRegistry>(account_address);
        let user = table::borrow(&user_registry.users, user_address);
        user.username
    }
}
