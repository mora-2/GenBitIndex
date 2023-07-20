#include <iostream>
#include <fstream>
#include <thread>
#include <vector>
#include <string>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <functional>

class ThreadPool
{
public:
    // 构造函数，创建线程池并启动指定数量的工作线程
    ThreadPool(int numThreads) : stop(false), taskCount(0)
    {
        for (int i = 0; i < numThreads; ++i)
        {
            threads.emplace_back(std::bind(&ThreadPool::workerThread, this));
        }
    }

    // 析构函数，销毁线程池
    ~ThreadPool()
    {
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            stop = true;
        }

        condition.notify_all();

        for (auto &t : threads)
        {
            t.join();
        }
    }

    // 提交任务到线程池
    template <typename F>
    void enqueue(F &&f)
    {
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            tasks.emplace(std::forward<F>(f));
            ++taskCount;
        }
        condition.notify_one(); // 主线程唤醒等待状态的子线程(32个)
    }
    void wait()
    {
        std::unique_lock<std::mutex> lock(queue_mutex);
        condition.wait(lock, [this]()
                       { return taskCount == 0; });
    }

private:
    // 工作线程函数，不断从任务队列中获取并执行任务，直到线程池停止运行
    void workerThread()
    {
        while (true)
        {
            std::function<void()> task;
            {
                std::unique_lock<std::mutex> lock(queue_mutex);
                /* 如果条件不满足，则当前线程会等待在条件变量上，直到有另一个线程满足条件并通知当前线程。
                   条件不满足时，线程会将自己放到条件变量的等待队列中，然后释放持有的互斥锁，进入等待状态。
                   当stop为true，或者任务队列不为空时线程被唤醒
                */
                condition.wait(lock, [this]()
                               { return stop || !tasks.empty(); });
                if (stop && tasks.empty())
                {
                    return;
                }
                task = std::move(tasks.front());
                tasks.pop();
            }
            task();
            {
                std::unique_lock<std::mutex> lock(queue_mutex);
                --taskCount;
                if (taskCount == 0)
                {
                    condition.notify_all();
                }
            }
        }
    }

    std::vector<std::thread> threads;        // 工作线程集合
    std::queue<std::function<void()>> tasks; // 任务队列
    std::mutex queue_mutex;                  // 任务队列互斥锁
    std::condition_variable condition;       // 任务队列条件变量
    bool stop;                               // 是否停止运行线程池
    int taskCount;
};