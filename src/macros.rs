macro_rules! loop_until_some {
    ($e:expr) => {{
        let mut val;
        loop {
            val = $e;
            if val.is_some() {
                break;
            }
        }
        val.unwrap()
    }}
}
