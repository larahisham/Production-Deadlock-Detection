public class java_deadlock {
    private static final Object A = new Object();
    private static final Object B = new Object();

    public static void main(String[] args) throws Exception {
        Thread t1 = new Thread(() -> {
            try {
                Thread.sleep(20);
            } catch (InterruptedException ignored) {}
            synchronized (A) {
                try {
                    Thread.sleep(100);
                } catch (InterruptedException ignored) {}
                synchronized (B) {
                    // unreachable under deadlock
                }
            }
        }, "java_deadlock_t1");

        Thread t2 = new Thread(() -> {
            try {
                Thread.sleep(20);
            } catch (InterruptedException ignored) {}
            synchronized (B) {
                try {
                    Thread.sleep(100);
                } catch (InterruptedException ignored) {}
                synchronized (A) {
                    // unreachable under deadlock
                }
            }
        }, "java_deadlock_t2");

        t1.start();
        t2.start();
        t1.join();
        t2.join();
    }
}
