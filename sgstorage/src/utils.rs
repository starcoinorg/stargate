// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

/// prefix_next returns the next prefix key.
///
/// Assume there are keys like:
///
///   rowkey1
///   rowkey1_column1
///   rowkey1_column2
///   rowKey2
///
/// If we seek 'rowkey1' Next, we will get 'rowkey1_column1'.
/// If we seek 'rowkey1' PrefixNext, we will get 'rowkey2'.
pub fn prefix_next(data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::from(data);
    let mut not_full = false;
    for d in buf.iter_mut().rev() {
        if let Some(v) = d.checked_add(1) {
            *d = v;
            not_full = true;
            break;
        } else {
            *d = 0;
        }
    }
    if !not_full {
        buf.copy_from_slice(data);
        buf.push(0u8);
    }
    buf
}

#[test]
fn test_prefix_next() {
    let prefix = vec![0u8, 1, 2, 3];
    assert_eq!(vec![0, 1, 2, 4], prefix_next(&prefix));
    let prefix = vec![0u8, 1, 2, 255];
    assert_eq!(vec![0, 1, 3, 0], prefix_next(&prefix));
    let prefix = vec![255u8, 255, 255, 255];
    assert_eq!(vec![255u8, 255, 255, 255, 0], prefix_next(&prefix));
}
