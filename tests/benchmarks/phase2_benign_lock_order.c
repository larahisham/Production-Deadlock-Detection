#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <unistd.h>

static pthread_mutex_t lock_a = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t lock_b = PTHREAD_MUTEX_INITIALIZER;
static atomic_int keep_running = 1;

static void *worker(void *arg)
{
    (void)arg;
    while (atomic_load(&keep_running)) {
        pthread_mutex_lock(&lock_a);
        usleep(1000);
        pthread_mutex_lock(&lock_b);
        usleep(1000);
        pthread_mutex_unlock(&lock_b);
        pthread_mutex_unlock(&lock_a);
        usleep(1000);
    }
    return NULL;
}

int main(void)
{
    pthread_t t1;
    pthread_t t2;

    if (pthread_create(&t1, NULL, worker, NULL) != 0)
        return 1;
    if (pthread_create(&t2, NULL, worker, NULL) != 0)
        return 1;

    sleep(6);
    atomic_store(&keep_running, 0);

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    printf("phase2_benign_lock_order complete\n");
    return 0;
}
