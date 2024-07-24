module secure_contract::secure_transfer_test {
    use std::signer;
    use aptos_framework::coin::{mint, burn};
    use secure_contract::secure_transfer;

    #[test(account = @0x1)]
    public entry fun test_secure_transfer(sender: signer) {
        let recipient = @0x2;
        let amount = 100;

        mint(sender, amount);
        secure_transfer::secure_transfer(sender, recipient, amount);

        // 검증 로직 추가 (예: 전송 로그 확인 등)
    }
}
