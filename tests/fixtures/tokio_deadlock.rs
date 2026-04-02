use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    let a = Arc::new(Mutex::new(()));
    let b = Arc::new(Mutex::new(()));

    let a1 = Arc::clone(&a);
    let b1 = Arc::clone(&b);
    let h1 = tokio::spawn(async move {
        sleep(Duration::from_millis(20)).await;
        let _ga = a1.lock().await;
        sleep(Duration::from_millis(100)).await;
        let _gb = b1.lock().await;
    });

    let a2 = Arc::clone(&a);
    let b2 = Arc::clone(&b);
    let h2 = tokio::spawn(async move {
        sleep(Duration::from_millis(20)).await;
        let _gb = b2.lock().await;
        sleep(Duration::from_millis(100)).await;
        let _ga = a2.lock().await;
    });

    let _ = tokio::join!(h1, h2);
}
