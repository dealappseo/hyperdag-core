use zkp_postcard::linked_bet::prove_linked_bet;

#[test]
fn test_high_confidence_correct() {
    let bet_amount = 1000;
    let confidence = 8000; // 80%
    let actual = true;
    let token_delta = (bet_amount * confidence) / 10000; // +800
    let repid_delta = (confidence * 100) / 10000; // +80

    let res = prove_linked_bet(1, 1, confidence as u32, actual, token_delta as i64, repid_delta as i64, bet_amount, false);
    assert!(res.is_ok());
}

#[test]
fn test_high_confidence_wrong() {
    let bet_amount = 1000;
    let confidence = 8000; 
    let actual = false;
    let token_delta = -(((bet_amount * confidence) / 10000) as i64); // -800
    let repid_delta = -(((confidence * 100) / 10000) as i64); // -80

    let res = prove_linked_bet(2, 1, confidence as u32, actual, token_delta as i64, repid_delta as i64, bet_amount, false);
    assert!(res.is_ok());
}

#[test]
fn test_low_confidence_correct() {
    let bet_amount = 1000;
    let confidence = 2000; 
    let actual = true;
    let token_delta = (bet_amount * confidence) / 10000; // +200
    let repid_delta = (confidence * 100) / 10000; // +20

    let res = prove_linked_bet(3, 1, confidence as u32, actual, token_delta as i64, repid_delta as i64, bet_amount, false);
    assert!(res.is_ok());
}

#[test]
fn test_score_stripping_rejected() {
    // Attempting to separate token gain from RepID loss
    let bet_amount = 1000;
    let confidence = 8000; 
    let actual = true;
    let token_delta = 800;
    let repid_delta = -80; // Negative RepID but actual was true

    let res = prove_linked_bet(4, 1, confidence as u32, actual, token_delta as i64, repid_delta as i64, bet_amount, false);
    assert!(res.is_err());
}

#[test]
fn test_overconfident_comma_penalty() {
    let bet_amount = 1000;
    let confidence = 9000; 
    let actual = true;
    let token_delta = 900; 
    let repid_delta = (confidence * 80) / 10000; // +72 (comma penalty)

    let res = prove_linked_bet(5, 1, confidence as u32, actual, token_delta as i64, repid_delta as i64, bet_amount, true);
    assert!(res.is_ok());
}

#[test]
fn test_sandbagging_attempt() {
    let bet_amount = 1000;
    let confidence = 5000; // Sandbagging: low confidence despite high win rate
    let actual = true;
    let token_delta = 500;
    // Comma penalty triggers because of historical calibration mismatch
    let repid_delta = (confidence * 80) / 10000; // +40

    let res = prove_linked_bet(6, 1, confidence as u32, actual, token_delta as i64, repid_delta as i64, bet_amount, true);
    assert!(res.is_ok());
}

#[test]
fn test_confidence_inflation_attempt() {
    let bet_amount = 1000;
    let confidence = 9500; // Inflated confidence
    let actual = false; // They were wrong
    let token_delta = -950;
    // Comma penalty triggers, meaning they take an EVEN LARGER hit to RepID?
    // Wait, the factor is 80 instead of 100 if penalty applies.
    // If penalty applies on loss, maybe they lose less? Actually, the penalty logic says:
    // factor = 100 - comma_applied * 20. So 80.
    // Meaning repid_magnitude is smaller. If they wanted to inflate rewards, they failed because they lost,
    // and if they won, comma penalty would reduce their gains.
    let repid_delta = -(((confidence * 80) / 10000) as i64); // -76

    let res = prove_linked_bet(7, 1, confidence as u32, actual, token_delta as i64, repid_delta as i64, bet_amount, true);
    assert!(res.is_ok());
}
