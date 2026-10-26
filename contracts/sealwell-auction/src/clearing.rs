//! Uniform-price clearing for a single pair (base/quote). Prices are integer quote units per base unit.
use near_sdk::json_types::U128;
use near_sdk::near;

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq, Copy)]
#[serde(rename_all = "lowercase")]
pub enum Side { Buy, Sell }

/// Bid plaintext, e.g. `{"side":"buy","price":"250","qty":"10"}`.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Order { pub side: Side, pub price: U128, pub qty: U128 }

#[derive(Debug, PartialEq, Eq)]
pub struct Clearing { pub price: u128, pub volume: u128, pub fills: Vec<(usize, u128)> }

/// Choose the price maximising matched volume (ties → lowest such price).
/// Buyers with limit ≥ p and sellers with limit ≤ p trade at p; the long side is filled
/// by price priority, then bid index (time priority).
pub fn clear_uniform(orders: &[(usize, Order)]) -> Option<Clearing> {
    let mut prices: Vec<u128> = orders.iter().map(|(_, o)| o.price.0).collect();
    prices.sort();
    prices.dedup();
    let mut best: Option<(u128, u128)> = None;
    for &p in &prices {
        let d: u128 = orders.iter().filter(|(_, o)| o.side == Side::Buy && o.price.0 >= p).map(|(_, o)| o.qty.0).sum();
        let s: u128 = orders.iter().filter(|(_, o)| o.side == Side::Sell && o.price.0 <= p).map(|(_, o)| o.qty.0).sum();
        let v = d.min(s);
        if v > 0 && best.map_or(true, |(_, bv)| v > bv) { best = Some((p, v)); }
    }
    let (price, volume) = best?;
    let mut fills = vec![];
    for side in [Side::Buy, Side::Sell] {
        let mut elig: Vec<&(usize, Order)> = orders.iter().filter(|(_, o)| o.side == side && match side {
            Side::Buy => o.price.0 >= price, Side::Sell => o.price.0 <= price }).collect();
        elig.sort_by(|a, b| match side {
            Side::Buy => b.1.price.0.cmp(&a.1.price.0), Side::Sell => a.1.price.0.cmp(&b.1.price.0) }.then(a.0.cmp(&b.0)));
        let mut left = volume;
        for (i, o) in elig { if left == 0 { break; } let q = o.qty.0.min(left); left -= q; fills.push((*i, q)); }
    }
    Some(Clearing { price, volume, fills })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn o(side: Side, p: u128, q: u128) -> Order { Order { side, price: U128(p), qty: U128(q) } }
    #[test]
    fn crosses_at_volume_max_price() {
        let r = clear_uniform(&[(0, o(Side::Buy, 300, 10)), (1, o(Side::Sell, 250, 10)), (2, o(Side::Sell, 320, 5))]).unwrap();
        assert_eq!((r.price, r.volume), (250, 10));
        assert_eq!(r.fills, vec![(0, 10), (1, 10)]);
    }
    #[test]
    fn partial_fill_long_side() {
        let r = clear_uniform(&[(0, o(Side::Buy, 300, 4)), (1, o(Side::Buy, 280, 4)), (2, o(Side::Sell, 270, 6))]).unwrap();
        assert_eq!(r.volume, 6);
        assert_eq!(r.fills, vec![(0, 4), (1, 2), (2, 6)]);
    }
    #[test]
    fn no_cross() {
        assert!(clear_uniform(&[(0, o(Side::Buy, 100, 1)), (1, o(Side::Sell, 200, 1))]).is_none());
    }
}
