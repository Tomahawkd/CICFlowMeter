package io.tomahawkd.cic.thread;

import io.tomahawkd.cic.flow.FlowGenerator;
import io.tomahawkd.cic.packet.PacketInfo;

import java.util.Deque;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class SimpleDispatchFlowWorker implements DispatchFlowWorker {

    private final FlowGenerator flowGenerator;
    private boolean working;
    private final Lock workingLock = new ReentrantLock();

    private final Deque<PacketInfo> queue;

    public SimpleDispatchFlowWorker(FlowGenerator flowGenerator) {
        this.flowGenerator = flowGenerator;
        this.working = false;
        this.queue = new ConcurrentLinkedDeque<>();
    }

    @Override
    public boolean containsFlow(PacketInfo info) {
        synchronized (flowGenerator) {
            return flowGenerator.containsFlow(info);
        }
    }

    @Override
    public void accept(PacketInfo info) {
        if (!this.working) return;
        queue.add(info);
    }

    @Override
    public long getWorkload() {
        return queue.size() + getFlowCount();
    }

    @Override
    public long getFlowCount() {
        synchronized (flowGenerator) {
            return flowGenerator.getFlowCount();
        }
    }

    @Override
    public void run() {
        this.working = true;

        workingLock.lock();
        while (this.working) {
            workingLock.unlock();
            if (!queue.isEmpty()) {
                synchronized (this.flowGenerator) {
                    flowGenerator.addPacket(queue.pop());
                }
            }
            workingLock.lock();
        }
        workingLock.unlock();

        while (!queue.isEmpty()) {
            synchronized (this.flowGenerator) {
                flowGenerator.addPacket(queue.pop());
            }
        }

        synchronized (this.flowGenerator) {
            flowGenerator.dumpLabeledCurrentFlow();
        }
    }

    @Override
    public void close() {
        workingLock.lock();
        this.working = false;
        workingLock.unlock();
    }

    @Override
    public void forceClose() {
        this.queue.clear();
        close();
    }
}
