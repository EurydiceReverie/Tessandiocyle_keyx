// dummy.rs to test linking a C object file
#[link(name = "test_obj", kind = "static")]
extern "C" {
    fn barrett_reduce(a: i16) -> i16;
}

fn main() {
    unsafe {
        let r = barrett_reduce(5000);
        println!("{}", r);
    }
}
