//! XTEST Unicode input using session-stable spare keycodes. Mapping ownership
//! is explicit: a delayed target must not see a restored/reused keycode for a
//! different character. No clipboard, shell, or input-method configuration is
//! used. Finite spare-keycode capacity is checked before any text is sent.
use crate::denied;
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
};
use x11rb::{
    connection::Connection,
    protocol::{
        xkb::{self, ConnectionExt as _},
        xproto::{self, ConnectionExt as _},
        xtest::ConnectionExt as _,
    },
};

fn error(e: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::other(e)
}
fn keysym(character: char) -> io::Result<u32> {
    Ok(match character {
        '\n' | '\r' => 0xff0d,
        '\t' => 0xff09,
        c if c.is_control() => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "control character is not a text commit",
            ));
        }
        c if u32::from(c) <= 0xff => u32::from(c),
        c => 0x0100_0000 | u32::from(c),
    })
}
struct Reservation {
    symbol: u32,
    expected: Vec<u32>,
    confirmed: bool,
}
pub(crate) struct X11Text {
    first: u8,
    count: u8,
    width: u8,
    original: Vec<u32>,
    expected: Vec<u32>,
    spare: Vec<u8>,
    reserved: BTreeMap<u8, Reservation>,
    held: Option<u8>,
    terminal: bool,
}
impl X11Text {
    pub(crate) fn new<C: Connection>(conn: &C) -> io::Result<Self> {
        let first = conn.setup().min_keycode;
        let count = conn
            .setup()
            .max_keycode
            .checked_sub(first)
            .and_then(|v| v.checked_add(1))
            .ok_or_else(|| denied("X11 keyboard range invalid"))?;
        let map = conn
            .get_keyboard_mapping(first, count)
            .map_err(error)?
            .reply()
            .map_err(error)?;
        if map.keysyms_per_keycode == 0
            || map.keysyms.len() > 8192
            || map.keysyms.len() != usize::from(count) * usize::from(map.keysyms_per_keycode)
        {
            return Err(denied("X11 keyboard mapping exceeds text budget"));
        }
        let modifiers = conn
            .get_modifier_mapping()
            .map_err(error)?
            .reply()
            .map_err(error)?
            .keycodes;
        let spare = map
            .keysyms
            .chunks(usize::from(map.keysyms_per_keycode))
            .enumerate()
            .filter_map(|(index, row)| {
                let code = first.checked_add(u8::try_from(index).ok()?)?;
                (row.iter().all(|s| *s == 0) && !modifiers.contains(&code)).then_some(code)
            })
            .collect();
        Ok(Self {
            first,
            count,
            width: map.keysyms_per_keycode,
            original: map.keysyms.clone(),
            expected: map.keysyms,
            spare,
            reserved: BTreeMap::new(),
            held: None,
            terminal: false,
        })
    }
    /// Canonicalize only our exact owned rows before the adapter compares its
    /// immutable baseline facts. Any unrelated mapping change remains fatal.
    pub(crate) fn canonicalize(&self, mapping: &mut Vec<u32>) -> io::Result<()> {
        if self.terminal {
            return Err(denied("X11 text adapter is terminal"));
        }
        if *mapping != self.expected {
            return Err(denied("X11 text keyboard mapping changed"));
        }
        mapping.clone_from(&self.original);
        Ok(())
    }
    pub(crate) fn needs_cleanup(&self) -> bool {
        self.held.is_some() || !self.reserved.is_empty()
    }
    fn row(&self, code: u8) -> std::ops::Range<usize> {
        let start = usize::from(code - self.first) * usize::from(self.width);
        start..start + usize::from(self.width)
    }
    fn code(&self, symbol: u32) -> Option<u8> {
        self.reserved
            .iter()
            .find_map(|(code, reservation)| (reservation.symbol == symbol).then_some(*code))
            .or_else(|| {
                self.original
                    .chunks(usize::from(self.width))
                    .enumerate()
                    .find_map(|(index, row)| (row[0] == symbol).then(|| self.first + index as u8))
            })
    }
    fn stable<C: Connection>(&self, conn: &C, focus: Option<u32>) -> io::Result<u32> {
        let state = conn
            .xkb_get_state(xkb::ID::USE_CORE_KBD.into())
            .map_err(error)?
            .reply()
            .map_err(error)?;
        // Core column zero is only unambiguous in group zero with no active,
        // latched, or locked modifiers. Never alter the user's locks or IME.
        if u16::from(state.mods) != 0
            || u16::from(state.base_mods) != 0
            || u16::from(state.latched_mods) != 0
            || u16::from(state.locked_mods) != 0
            || u8::from(state.group) != 0
            || state.base_group != 0
            || state.latched_group != 0
            || u8::from(state.locked_group) != 0
            || u16::from(state.ptr_btn_state) != 0
        {
            return Err(denied(
                "X11 text requires released modifiers/buttons and the base keyboard group",
            ));
        }
        let keys = conn
            .query_keymap()
            .map_err(error)?
            .reply()
            .map_err(error)?
            .keys;
        if keys.iter().any(|byte| *byte != 0) {
            return Err(denied("X11 text requires all physical keys released"));
        }
        let current = conn
            .get_input_focus()
            .map_err(error)?
            .reply()
            .map_err(error)?
            .focus;
        if current <= 1 || focus.is_some_and(|focus| focus != current) {
            return Err(denied("X11 text target focus is absent or changed"));
        }
        Ok(current)
    }
    fn mapping<C: Connection>(&self, conn: &C) -> io::Result<Vec<u32>> {
        let map = conn
            .get_keyboard_mapping(self.first, self.count)
            .map_err(error)?
            .reply()
            .map_err(error)?;
        if map.keysyms_per_keycode != self.width || map.keysyms.len() != self.original.len() {
            return Err(denied("X11 text keyboard shape changed"));
        }
        Ok(map.keysyms)
    }
    fn commit_inner<C: Connection>(&mut self, conn: &C, root: u32, text: &str) -> io::Result<()> {
        if text.is_empty() || text.len() > 16 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "X11 text exceeds commit budget",
            ));
        }
        let symbols: Vec<_> = text.chars().map(keysym).collect::<io::Result<_>>()?;
        let missing: BTreeSet<_> = symbols
            .iter()
            .copied()
            .filter(|symbol| self.code(*symbol).is_none())
            .collect();
        let available: Vec<_> = self
            .spare
            .iter()
            .copied()
            .filter(|code| !self.reserved.contains_key(code))
            .collect();
        if missing.len() > available.len() {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "X11 session has insufficient stable Unicode keycodes; text was not sent",
            ));
        }
        if self.mapping(conn)? != self.expected {
            return Err(denied("X11 keyboard changed before text commit"));
        }
        let focus = self.stable(conn, None)?;
        for (symbol, code) in missing.into_iter().zip(available) {
            let row = vec![symbol; usize::from(self.width)];
            // Record ownership before a potentially partially dispatched call.
            self.reserved.insert(
                code,
                Reservation {
                    symbol,
                    expected: row.clone(),
                    confirmed: false,
                },
            );
            conn.change_keyboard_mapping(1, code, self.width, &row)
                .map_err(error)?
                .check()
                .map_err(error)?;
            let actual = self.mapping(conn)?;
            let range = self.row(code);
            let mut expected = self.expected.clone();
            expected[range.clone()].copy_from_slice(&actual[range.clone()]);
            if actual != expected
                || actual[range.clone()].first() != Some(&symbol)
                || actual[range.clone()]
                    .iter()
                    .any(|v| *v != 0 && *v != symbol)
            {
                return Err(denied(
                    "X11 server did not preserve the owned Unicode mapping",
                ));
            }
            if let Some(reservation) = self.reserved.get_mut(&code) {
                reservation.expected = actual[range].to_vec();
                reservation.confirmed = true;
            }
            self.expected = actual;
        }
        for symbol in symbols {
            self.stable(conn, Some(focus))?;
            let code = self
                .code(symbol)
                .ok_or_else(|| denied("X11 text reservation missing"))?;
            self.held = Some(code);
            conn.xtest_fake_input(
                xproto::KEY_PRESS_EVENT,
                code,
                x11rb::CURRENT_TIME,
                root,
                0,
                0,
                0,
            )
            .map_err(error)?
            .check()
            .map_err(error)?;
            conn.xtest_fake_input(
                xproto::KEY_RELEASE_EVENT,
                code,
                x11rb::CURRENT_TIME,
                root,
                0,
                0,
                0,
            )
            .map_err(error)?
            .check()
            .map_err(error)?;
            self.held = None;
        }
        Ok(())
    }
    /// The caller owns the OS connection deadline and must have no held remote
    /// keys/buttons. A partial/error commit is terminal and must not be retried.
    pub(crate) fn commit<C: Connection>(
        &mut self,
        conn: &C,
        root: u32,
        text: &str,
    ) -> io::Result<()> {
        if self.terminal {
            return Err(denied("X11 text adapter is terminal"));
        }
        let result = self.commit_inner(conn, root, text);
        if result.is_err() {
            self.terminal = true;
        }
        result
    }
    /// Use only the original X server (including process start identity) and
    /// the caller's existing cleanup deadline. Preserve externally changed rows.
    pub(crate) fn reset<C: Connection>(&mut self, conn: &C, root: u32) -> io::Result<()> {
        self.terminal = true;
        let mut first_error = None;
        if let Some(code) = self.held {
            match conn
                .xtest_fake_input(
                    xproto::KEY_RELEASE_EVENT,
                    code,
                    x11rb::CURRENT_TIME,
                    root,
                    0,
                    0,
                    0,
                )
                .map_err(error)
                .and_then(|cookie| cookie.check().map_err(error))
            {
                Ok(()) => self.held = None,
                Err(error) => first_error = Some(error),
            }
        }
        for code in self.reserved.keys().copied().collect::<Vec<_>>() {
            let result = (|| {
                let map = self.mapping(conn)?;
                let range = self.row(code);
                let reservation = &self.reserved[&code];
                if map[range.clone()] == self.original[range.clone()] {
                    return Ok(());
                }
                // XKB may normalize repeated columns before the checked
                // request's reply is lost. An unconfirmed reservation can own
                // only its exact Unicode symbol (and server padding zeros).
                let owned = if reservation.confirmed {
                    map[range.clone()] == reservation.expected
                } else {
                    map[range.clone()].first() == Some(&reservation.symbol)
                        && map[range.clone()]
                            .iter()
                            .all(|s| *s == 0 || *s == reservation.symbol)
                };
                if !owned {
                    return Err(denied(
                        "X11 Unicode mapping ownership lost; external mapping preserved",
                    ));
                }
                conn.change_keyboard_mapping(1, code, self.width, &self.original[range.clone()])
                    .map_err(error)?
                    .check()
                    .map_err(error)?;
                self.expected[range.clone()].copy_from_slice(&self.original[range]);
                Ok(())
            })();
            match result {
                Ok(()) => {
                    self.reserved.remove(&code);
                }
                Err(error) if first_error.is_none() => first_error = Some(error),
                Err(_) => {}
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unicode_keysym_encoding_and_control_text_are_distinct() {
        assert_eq!(keysym('a').ok(), Some(97));
        assert_eq!(keysym('é').ok(), Some(0xe9));
        assert_eq!(keysym('中').ok(), Some(0x01004e2d));
        assert_eq!(keysym('😀').ok(), Some(0x0101f600));
        assert_eq!(keysym('\n').ok(), Some(0xff0d));
        assert_eq!(keysym('\t').ok(), Some(0xff09));
        assert!(keysym('\0').is_err());
        assert!(keysym('\u{1b}').is_err());
    }
}
