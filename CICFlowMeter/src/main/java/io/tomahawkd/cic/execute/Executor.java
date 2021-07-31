package io.tomahawkd.cic.execute;

import io.tomahawkd.cic.config.CommandlineDelegate;

public interface Executor {

    void execute(CommandlineDelegate delegate) throws Exception;
}
