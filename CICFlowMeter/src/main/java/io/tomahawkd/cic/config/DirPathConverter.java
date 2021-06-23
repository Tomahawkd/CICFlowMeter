package io.tomahawkd.cic.config;

import com.beust.jcommander.IStringConverter;
import com.beust.jcommander.ParameterException;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class DirPathConverter implements IStringConverter<Path> {
    @Override
    public Path convert(String value) {
        Path path = Paths.get(value);
        if (!Files.exists(path)) {
            try {
                Files.createDirectories(path);
            } catch (IOException e) {
                throw new ParameterException("Error occurs while creating directories.", e);
            }
        }

        if (!Files.isDirectory(path)) {
            throw new ParameterException("Not a directory.");
        }

        return path;
    }
}
