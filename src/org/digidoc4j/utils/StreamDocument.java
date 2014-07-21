package org.digidoc4j.utils;


import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.MimeType;
import org.digidoc4j.api.exceptions.DigiDoc4JException;
import sun.misc.IOUtils;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

public class StreamDocument implements DSSDocument {
    InputStream stream;
    String documentName;
    MimeType mimeType;

    public StreamDocument(InputStream stream, String documentName, MimeType mimeType) {
        this.stream = stream;
        this.documentName = documentName;
        this.mimeType = mimeType;
    }

    @Override
    public InputStream openStream() throws DSSException {
        return stream;
    }

    @Override
    public byte[] getBytes() throws DSSException {
        try {
            return IOUtils.readFully(stream, -1, true);
        } catch (IOException e) {
            throw new DigiDoc4JException(e);
        }
    }

    @Override
    public String getName() {
        return documentName;
    }

    @Override
    public String getAbsolutePath() {
        return documentName;
    }

    @Override
    public MimeType getMimeType() {
        return mimeType;
    }

    @Override
    public void setMimeType(MimeType mimeType) {
        this.mimeType = mimeType;
    }

    @Override
    public void save(String filePath) {
        try {
            FileOutputStream fileOutputStream = new FileOutputStream(filePath);
            try {
                byte[] buffer = new byte[4096];
                for (int n; (n = stream.read(buffer)) != -1; )
                    fileOutputStream.write(buffer, 0, n);
            }
            finally { fileOutputStream.close(); }
        } catch (IOException e) {
            throw new DigiDoc4JException(e);
        }
    }

    @Override
    public String getDigest(DigestAlgorithm digestAlgorithm) {
        final byte[] digestBytes = DSSUtils.digest(digestAlgorithm, getBytes());
        return DSSUtils.base64Encode(digestBytes);
    }
}
