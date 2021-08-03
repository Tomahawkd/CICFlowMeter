package io.tomahawkd.cic.source;

import java.nio.file.Files;
import java.nio.file.Path;

public class LocalSingleFile implements LocalFile {

    private final Path file;

    public LocalSingleFile(Path file) {
        this.file = file;
    }

    @Override
    public String getFileName() {
        return file.getFileName().toString();
    }

    @Override
    public Path getFilePath() {
        return file;
    }

    @Override
    public boolean exists() {
        return Files.exists(file);
    }

    @Override
    public boolean filenameContains(CharSequence seq) {
        return file.getFileName().toString().contains(seq);
    }

    @Override
    public String toString() {
        return "LocalSingleFile[" + "file=" + file.toAbsolutePath() + ']';
    }
}
