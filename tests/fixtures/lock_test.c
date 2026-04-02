#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

// Two mutexes for testing
pthread_mutex_t mutex_a = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex_b = PTHREAD_MUTEX_INITIALIZER;

// Control variables
volatile int keep_running = 1;
int iteration = 0;

void* thread_1_func(void *arg) {
    printf("[Thread 1] Starting\n");
    
    while (keep_running) {
        // Thread 1: Always acquire A then B
        printf("[Thread 1] Acquiring mutex_a...\n");
        pthread_mutex_lock(&mutex_a);
        printf("[Thread 1] Got mutex_a\n");
        
        // Simulate some work
        usleep(100000);  // 100ms
        
        printf("[Thread 1] Acquiring mutex_b...\n");
        pthread_mutex_lock(&mutex_b);
        printf("[Thread 1] Got mutex_b (A->B order)\n");
        
        // Critical section
        usleep(100000);
        
        printf("[Thread 1] Releasing mutex_b\n");
        pthread_mutex_unlock(&mutex_b);
        
        printf("[Thread 1] Releasing mutex_a\n");
        pthread_mutex_unlock(&mutex_a);
        
        iteration++;
        printf("[Thread 1] Iteration %d complete\n\n", iteration);
        
        usleep(500000);  // Wait before next iteration
    }
    
    return NULL;
}

void* thread_2_func(void *arg) {
    printf("[Thread 2] Starting\n");
    
    while (keep_running) {
        // Thread 2: Always acquire A then B (SAME order as Thread 1)
        printf("[Thread 2] Acquiring mutex_a...\n");
        pthread_mutex_lock(&mutex_a);
        printf("[Thread 2] Got mutex_a\n");
        
        // Simulate some work
        usleep(100000);
        
        printf("[Thread 2] Acquiring mutex_b...\n");
        pthread_mutex_lock(&mutex_b);
        printf("[Thread 2] Got mutex_b (A->B order)\n");
        
        // Critical section
        usleep(100000);
        
        printf("[Thread 2] Releasing mutex_b\n");
        pthread_mutex_unlock(&mutex_b);
        
        printf("[Thread 2] Releasing mutex_a\n");
        pthread_mutex_unlock(&mutex_a);
        
        printf("[Thread 2] Iteration complete\n\n");
        
        usleep(500000);
    }
    
    return NULL;
}

int main() {
    printf("========================================\n");
    printf("Lock Event Generator\n");
    printf("========================================\n");
    printf("This program generates lock events for eBPF monitoring\n");
    printf("Watch the maps in another terminal:\n");
    printf("  sudo bpftool map dump name held_locks_map\n");
    printf("  sudo bpftool map dump name lock_info_map\n");
    printf("========================================\n\n");
    
    pthread_t thread1, thread2;
    
    printf("Creating threads...\n");
    pthread_create(&thread1, NULL, thread_1_func, NULL);
    pthread_create(&thread2, NULL, thread_2_func, NULL);
    
    printf("Threads created. Running for 10 seconds...\n");
    printf("Press Ctrl+C to stop.\n\n");
    
    // Run for 10 seconds
    sleep(10);
    
    printf("\nStopping...\n");
    keep_running = 0;
    
    // Wait for threads
    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);
    
    printf("Done. Generated %d iterations.\n", iteration);
    
    return 0;
}