use zkp_postcard::trade_auth::prove_trade_auth;

#[test]
fn test_trade_within_authority() {
    let res = prove_trade_auth(
        8000, 1500, 1500, // agent scores (1.5 W, 1.5 C) => combined = 8000 * 1500 * 1500 / 1M = 18000
        6000, // builder repid
        10000, // builder stake => sqrt = 100
        10000, // threshold
        18000, // trade amount. authority = 100 * 18000 / 100 = 18000
        100, 50 // timestamp
    );
    assert!(res.is_ok());
}

#[test]
fn test_trade_exceeds_authority_low_repid() {
    let res = prove_trade_auth(
        1000, 1500, 1500, // agent scores => combined = 1000 * 1500 * 1500 / 1M = 2250
        6000, 10000, 1000,
        18000, // trade amount > authority (100 * 2250 / 100 = 2250)
        100, 50
    );
    assert_eq!(res.err(), Some("trade_amount > authority".into()));
}

#[test]
fn test_trade_exceeds_authority_low_wisdom() {
    let res = prove_trade_auth(
        8000, 100, 1500, // agent scores => combined = 1200
        6000, 10000, 1000,
        18000, 
        100, 50
    );
    assert_eq!(res.err(), Some("trade_amount > authority".into()));
}

#[test]
fn test_trade_exceeds_authority_low_character() {
    let res = prove_trade_auth(
        8000, 1500, 100, // agent scores => combined = 1200
        6000, 10000, 1000,
        18000, 
        100, 50
    );
    assert_eq!(res.err(), Some("trade_amount > authority".into()));
}

#[test]
fn test_builder_below_floor() {
    let res = prove_trade_auth(
        8000, 1500, 1500, 
        4000, // builder repid < 5000 floor
        10000, 1000, 18000, 100, 50
    );
    assert_eq!(res.err(), Some("builder_repid < floor".into()));
}
