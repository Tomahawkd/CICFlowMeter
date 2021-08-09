package io.tomahawkd.cic.label.factory;

import io.tomahawkd.cic.label.LabelStrategy;
import io.tomahawkd.cic.source.LocalFile;

public abstract class LabelStrategyFactory {

    public LabelStrategy getStrategy(LocalFile file) {
        return LabelStrategy.NONE;
    }
}
