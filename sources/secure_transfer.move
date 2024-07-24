module secure_contract::secure_transfer {
    use std::signer;
    use std::string::{String, utf8};
    use aptos_framework::coin::{Coin, withdraw, deposit};
    use aptos_framework::account;

    struct TransferLog has key {
        from: address,
        to: address,
        amount: u64,
    }

    public entry fun secure_transfer(
        sender: signer,
        recipient: address,
        amount: u64
    ) {
        let sender_address = signer::address_of(&sender);

        // 출금과 입금 작업을 안전하게 처리
        withdraw(sender, amount);
        deposit(recipient, amount);

        // 전송 기록을 저장
        move_to(
            &sender,
            TransferLog {
                from: sender_address,
                to: recipient,
                amount,
            },
        );
    }

    public fun get_transfer_log(sender_address: address): TransferLog {
        borrow_global<TransferLog>(sender_address)
    }
}
