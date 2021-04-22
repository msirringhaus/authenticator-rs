/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//use runloop::RunLoop;
use std::error::Error;

use super::TestCase;

pub struct Transaction {}

fn always_alive() -> bool {
    true
}

impl Transaction {
    pub fn new<F, EC>(_timeout: u64, _cbc: EC, new_device_cb: F) -> crate::Result<Self>
    where
        F: Fn(TestCase, &dyn Fn() -> bool) + Sync + Send + 'static,
    {
        let test_case = TestCase::active();
        new_device_cb(test_case, &always_alive);
        Ok(Self {})
    }

    pub fn cancel(&mut self) {}
}
