package io.tomahawkd.cic.thread;

import io.tomahawkd.cic.flow.FlowGenerator;
import io.tomahawkd.cic.packet.PacketInfo;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

public class PacketDispatcher {

    private static final Logger logger = LogManager.getLogger(PacketDispatcher.class);

    private final List<DispatchWorker> workers;
    private final ThreadPoolExecutor executor;
    private boolean working;

    public PacketDispatcher(int threads, Supplier<FlowGenerator> generatorFactory) {
        this.workers = new ArrayList<>();
        this.executor = (ThreadPoolExecutor) Executors.newFixedThreadPool(threads);
        this.working = false;
        for (int i = 0; i < threads; i++) {
            workers.add(new SimpleDispatchWorker(generatorFactory.get()));
        }
    }

    public void dispatch(PacketInfo info) {
        if (!this.working) return;

        // flow is processing
        for (DispatchWorker worker : workers) {
            if (worker.containsFlow(info)) {
                worker.accept(info);
                return;
            }
        }

        // new flow
        DispatchWorker worker = workers.stream().min(Comparator.comparingLong(DispatchWorker::getWorkload))
                .orElse(null);

        if (worker == null) {
            logger.fatal("No worker candidate.");
            throw new RuntimeException("No worker candidate.");
        }

        worker.accept(info);
    }

    public long getFlowCount() {
        return workers.stream().mapToLong(DispatchWorker::getFlowCount).sum();
    }

    public void start() {
        this.working = true;
        int count = 0;
        for (DispatchWorker worker : workers) {
            logger.info("Activating worker {}", ++count);
            executor.execute(worker);
        }
    }

    public void stop() {
        this.working = false;
        workers.forEach(DispatchWorker::close);
        executor.shutdown();
        try {
            if (!executor.awaitTermination(10, TimeUnit.MINUTES)) {
                workers.forEach(DispatchWorker::forceClose);
            }
        } catch (InterruptedException e) {
            logger.warn("Interrupted while waiting termination.");
        }
    }
}
