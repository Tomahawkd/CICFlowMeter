package io.tomahawkd.cic.source;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class LocalMultiFile implements LocalFile {

    private final List<LocalSingleFile> segments;

    private final Path parentDir;

    public LocalMultiFile(Path parentDir) {
        this.segments = new ArrayList<>();
        this.parentDir = parentDir;
    }

    public void addSegment(Path fileSegment) {
        this.segments.add(new LocalSingleFile(fileSegment));
    }

    public void addSegments(List<Path> fileSegments) {
        fileSegments.forEach(this::addSegment);
    }

    @Override
    public String getFileName() {
        return parentDir.getFileName().toString();
    }

    @Override
    public Path getFilePath() {
        return parentDir;
    }

    @Override
    public boolean exists() {
        for (LocalSingleFile segment : segments) {
            if (!segment.exists()) return false;
        }
        return true;
    }

    @Override
    public boolean filenameContains(CharSequence seq) {
        // requires all segment contains same substring
        for (LocalSingleFile segment : segments) {
            if (!segment.filenameContains(seq)) return false;
        }
        return true;
    }

    public List<LocalSingleFile> getSegments() {
        return segments;
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("LocalMultiFile[parentDir=").append(parentDir.toAbsolutePath()).append(", segments=[");
        segments.forEach(f -> builder.append(f).append(", "));
        builder.append("]]");
        return builder.toString();
    }
}
