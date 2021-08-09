package io.tomahawkd.cic.thread;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

public abstract class AbstractDispatcher implements Dispatcher {

    private static final Logger logger = LogManager.getLogger(AbstractDispatcher.class);

    protected final List<DispatchWorker> workers;

    protected boolean working;
    protected final ThreadPoolExecutor executor;
    protected final long queueSize;

    protected AbstractDispatcher(int threads, long queueSize) {
        this.queueSize = queueSize;
        this.executor = (ThreadPoolExecutor) Executors.newFixedThreadPool(threads);
        this.workers = new ArrayList<>();
        this.working = false;
    }

    public void start() {
        this.working = true;
        int count = 0;
        for (DispatchWorker worker : workers) {
            logger.info("Activating worker {}-{}", worker.getClass(), ++count);
            executor.execute(worker);
        }
    }

    public void stop() {
        this.working = false;
        workers.forEach(DispatchWorker::close);
        executor.shutdown();
    }

    public boolean running() {
        return !executor.isTerminated();
    }

    public void forceStop() {
        try {
            if (running()) {
                workers.forEach(DispatchWorker::forceClose);
                if (!executor.awaitTermination(30, TimeUnit.SECONDS)) {
                    logger.warn("30 waiting seconds elapsed, shutdown forcibly.");
                    executor.shutdownNow();
                }
            }
        } catch (InterruptedException e) {
            logger.warn("Interrupted while waiting termination.");
        }
    }

    public void waitForWorker(DispatchWorker worker) {
        while (worker.getWorkload() > queueSize) {
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                logger.warn("Waiting for Worker is interrupted.");
            }
        }
    }

    public DispatchWorker getLowestWorkloadWorker() {
        DispatchWorker worker;
        do {
            worker = workers.stream()
                    .min(Comparator.comparingLong(DispatchWorker::getWorkload))
                    .orElse(null);

            if (worker == null) {
                logger.fatal("No worker candidate.");
                throw new RuntimeException("No worker candidate.");
            }

        } while (worker.getWorkload() > queueSize);

        logger.debug("Acquire worker {} with workload {}", worker.getClass(), worker.getWorkload());
        return worker;
    }
}
