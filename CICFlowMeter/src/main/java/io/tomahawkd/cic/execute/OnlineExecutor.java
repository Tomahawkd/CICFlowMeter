package io.tomahawkd.cic.execute;

import io.tomahawkd.cic.config.CommandlineDelegate;

@WithMode(ExecutionMode.ONLINE)
public class OnlineExecutor extends AbstractExecutor {

    public OnlineExecutor() {
        super();
    }

    @Override
    public void execute(CommandlineDelegate delegate) throws Exception {
        throw new IllegalStateException("Not Implement yet.");
    }
}
