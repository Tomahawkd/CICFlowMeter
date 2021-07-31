package io.tomahawkd.cic.config;

import com.beust.jcommander.IStringConverter;
import io.tomahawkd.cic.execute.ExecutionMode;

import java.util.Locale;

public class ExecutionModeConverter implements IStringConverter<ExecutionMode> {

    @Override
    public ExecutionMode convert(String value) {
        try {
            return ExecutionMode.valueOf(value.toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            // default value
            return ExecutionMode.DEFAULT;
        }
    }
}
