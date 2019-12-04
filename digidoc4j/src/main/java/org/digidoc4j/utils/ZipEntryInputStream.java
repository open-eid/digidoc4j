package org.digidoc4j.utils;

import java.io.IOException;
import java.io.InputStream;
import java.util.zip.ZipInputStream;

/**
 * Closing this wrapper stream does not close the underlying ZipInputStream.
 * It merely calls <code>closeEntry()</code> on the underlying ZipInputStream.
 */
public class ZipEntryInputStream extends InputStream {

    private final ZipInputStream zipInputStream;

    public ZipEntryInputStream(ZipInputStream zipInputStream) {
        this.zipInputStream = zipInputStream;
    }

    @Override
    public int available() throws IOException {
        return zipInputStream.available();
    }

    @Override
    public void close() throws IOException {
        zipInputStream.closeEntry();
    }

    @Override
    public void mark(int readlimit) {
        zipInputStream.mark(readlimit);
    }

    @Override
    public boolean markSupported() {
        return zipInputStream.markSupported();
    }

    @Override
    public int read() throws IOException {
        return zipInputStream.read();
    }

    @Override
    public int read(byte[] b) throws IOException {
        return zipInputStream.read(b);
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        return zipInputStream.read(b, off, len);
    }

    @Override
    public void reset() throws IOException {
        zipInputStream.reset();
    }

    @Override
    public long skip(long n) throws IOException {
        return zipInputStream.skip(n);
    }

}
