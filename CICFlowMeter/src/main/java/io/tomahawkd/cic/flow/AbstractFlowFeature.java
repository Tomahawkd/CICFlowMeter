package io.tomahawkd.cic.flow;

import org.apache.commons.lang3.StringUtils;
import org.jetbrains.annotations.NotNull;

import java.util.Arrays;

public abstract class AbstractFlowFeature implements FlowFeature {

    private final FlowFeatureTag[] headers;
    protected final FlowBasicFeature basicInfo;

    public AbstractFlowFeature(@NotNull FlowFeatureTag[] headers) {
        this(null, headers);
    }

    public AbstractFlowFeature(FlowBasicFeature basicInfo, @NotNull FlowFeatureTag[] headers) {
        this.basicInfo = basicInfo;
        this.headers = headers;
    }

    @Override
    public String headers() {
        return Arrays.stream(headers).map(FlowFeatureTag::getName).reduce("", (r, s) -> r + s + ",");
    }

    @Override
    public String exportData() {
        return StringUtils.repeat("0,", columnCount());
    }

    @Override
    public int columnCount() {
        return headers.length;
    }

    protected final void addZeroesToBuilder(StringBuilder builder, int count) {
        for (int i = 0; i < count; i++) {
            builder.append(0).append(SEPARATOR);
        }
    }
}
