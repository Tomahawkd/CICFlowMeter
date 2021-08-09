package io.tomahawkd.cic.thread;

import io.tomahawkd.cic.flow.FlowGenerator;
import io.tomahawkd.cic.packet.PacketInfo;

import java.util.Deque;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class SimpleDispatchWorker implements DispatchWorker {

    private final FlowGenerator flowGenerator;
    private boolean working;
    private final Lock workingLock = new ReentrantLock();
    private final Lock flowLock = new ReentrantLock();

    private final Deque<PacketInfo> queue;

    public SimpleDispatchWorker(FlowGenerator flowGenerator) {
        this.flowGenerator = flowGenerator;
        this.working = false;
        this.queue = new ConcurrentLinkedDeque<>();
    }

    @Override
    public boolean containsFlow(PacketInfo info) {
        flowLock.lock();
        boolean contains = flowGenerator.containsFlow(info);
        flowLock.unlock();
        return contains;
    }

    @Override
    public void accept(PacketInfo info) {
        queue.add(info);
    }

    @Override
    public long getWorkload() {
        return queue.size() + getFlowCount();
    }

    @Override
    public long getFlowCount() {
        flowLock.lock();
        long flows = flowGenerator.getFlowCount();
        flowLock.unlock();
        return flows;
    }

    @Override
    public void run() {
        this.working = true;

        workingLock.lock();
        while (this.working) {
            workingLock.unlock();
            if (!queue.isEmpty()) {
                flowLock.lock();
                flowGenerator.addPacket(queue.pop());
                flowLock.unlock();
            }
            workingLock.lock();
        }
        workingLock.unlock();

        while (!queue.isEmpty()) {
            flowGenerator.addPacket(queue.pop());
        }
        flowGenerator.dumpLabeledCurrentFlow();
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
