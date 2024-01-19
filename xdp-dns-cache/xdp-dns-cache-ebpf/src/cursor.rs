pub struct Cursor {
    pub pos: usize,
}

impl Cursor {
    pub fn new(pos: usize) -> Self {
        Self { pos }
    }
}
