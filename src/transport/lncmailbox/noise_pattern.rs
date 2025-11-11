#![cfg(feature = "transport-mailbox")]

//! Noise handshake pattern descriptors for LNC (XX and KK with SPAKE2).

#[derive(Clone, Copy, Debug)]
pub enum Token {
    E,
    S,
    Ee,
    Es,
    Se,
    Ss,
    Me,
}

#[derive(Clone, Copy, Debug)]
pub struct MessagePattern {
    pub tokens: &'static [Token],
    pub initiator: bool,
    pub act: u8,
}

#[derive(Clone, Debug)]
pub struct HandshakePattern {
    pub name: &'static str,
    pub pre_messages: &'static [MessagePattern],
    pub pattern: &'static [MessagePattern],
}

fn pattern_xx() -> HandshakePattern {
    const ACT1: MessagePattern = MessagePattern {
        tokens: &[Token::Me],
        initiator: true,
        act: 1,
    };
    const ACT2: MessagePattern = MessagePattern {
        tokens: &[Token::E, Token::Ee, Token::S, Token::Es],
        initiator: false,
        act: 2,
    };
    const ACT3: MessagePattern = MessagePattern {
        tokens: &[Token::S, Token::Se],
        initiator: true,
        act: 3,
    };
    HandshakePattern {
        name: "XXeke+SPAKE2",
        pre_messages: &[],
        pattern: &[ACT1, ACT2, ACT3],
    }
}

fn pattern_kk() -> HandshakePattern {
    const PRE1: MessagePattern = MessagePattern {
        tokens: &[Token::S],
        initiator: true,
        act: 0,
    };
    const PRE2: MessagePattern = MessagePattern {
        tokens: &[Token::S],
        initiator: false,
        act: 0,
    };
    const ACT1: MessagePattern = MessagePattern {
        tokens: &[Token::E, Token::Es, Token::Ss],
        initiator: true,
        act: 1,
    };
    const ACT2: MessagePattern = MessagePattern {
        tokens: &[Token::E, Token::Ee, Token::Se],
        initiator: false,
        act: 2,
    };
    HandshakePattern {
        name: "KK",
        pre_messages: &[PRE1, PRE2],
        pattern: &[ACT1, ACT2],
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PatternRef {
    Xx,
    Kk,
}

impl PatternRef {
    #[must_use]
    pub fn pattern(&self) -> HandshakePattern {
        match self {
            PatternRef::Xx => pattern_xx(),
            PatternRef::Kk => pattern_kk(),
        }
    }
}
