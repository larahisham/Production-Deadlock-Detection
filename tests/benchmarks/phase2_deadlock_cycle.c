#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

static pthread_mutex_t lock_a = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t lock_b = PTHREAD_MUTEX_INITIALIZER;

static void *thread_ab(void *arg)
{
    (void)arg;
    usleep(20000);
    pthread_mutex_lock(&lock_a);
    usleep(100000);
    pthread_mutex_lock(&lock_b);
    return NULL;
}

static void *thread_ba(void *arg)
{
    (void)arg;
    usleep(20000);
    pthread_mutex_lock(&lock_b);
    usleep(100000);
    pthread_mutex_lock(&lock_a);
    return NULL;
}

int main(void)
{
    pthread_t t1;
    pthread_t t2;

    if (pthread_create(&t1, NULL, thread_ab, NULL) != 0)
        return 1;
    if (pthread_create(&t2, NULL, thread_ba, NULL) != 0)
        return 1;

    /* Keep process alive while both threads deadlock so loader can emit active-block alerts. */
    sleep(8);
    printf("phase2_deadlock_cycle timeout reached\n");
    return 0;
}
