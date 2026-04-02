use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

fn main() {
    let a = Arc::new(Mutex::new(()));
    let b = Arc::new(Mutex::new(()));

    let a1 = Arc::clone(&a);
    let b1 = Arc::clone(&b);
    let t1 = thread::spawn(move || {
        thread::sleep(Duration::from_millis(20));
        let _ga = a1.lock().unwrap();
        thread::sleep(Duration::from_millis(100));
        let _gb = b1.lock().unwrap();
    });

    let a2 = Arc::clone(&a);
    let b2 = Arc::clone(&b);
    let t2 = thread::spawn(move || {
        thread::sleep(Duration::from_millis(20));
        let _gb = b2.lock().unwrap();
        thread::sleep(Duration::from_millis(100));
        let _ga = a2.lock().unwrap();
    });

    let _ = t1.join();
    let _ = t2.join();
}
