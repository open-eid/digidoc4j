package org.digidoc4j.ddoc.factory;

import org.digidoc4j.ddoc.DigiDocException;
import org.digidoc4j.ddoc.Signature;
import org.digidoc4j.ddoc.SignedDoc;

import java.io.InputStream;
import java.util.List;

public interface DigiDocFactory {

    /**
     * initializes the implementation class
     */
    void init()
            throws DigiDocException;

    /**
     * Reads in a DigiDoc file
     * @param fileName file name
     * @return signed document object if successfully parsed
     */
    SignedDoc readSignedDoc(String fileName)
            throws DigiDocException;

    /**
     * Reads in a DigiDoc or BDOC from stream. In case of BDOC a Zip stream will be
     * constructed to read this input stream. In case of ddoc a normal saxparsing stream
     * will be used.
     * @param is opened stream with DigiDoc/BDOC data
     * The user must open and close it.
     * @return signed document object if successfully parsed
     */
    SignedDoc readSignedDocFromStream(InputStream is)
            throws DigiDocException;

    /**
     * Reads in a DigiDoc or BDOC file
     * @param fname filename
     * @param lerr list of errors to be filled. If not null then no exceptions are thrown
     * but returned in this array
     * @return signed document object if successfully parsed
     */
    SignedDoc readSignedDoc(String fname, List lerr)
            throws DigiDocException;

    /**
     * Reads in a DigiDoc or BDOC from stream. In case of BDOC a Zip stream will be
     * constructed to read this input stream. In case of ddoc a normal saxparsing stream
     * will be used.
     * @param is opened stream with DigiDoc/BDOC data
     * The user must open and close it.
     * @param lerr list of errors to be filled. If not null then no exceptions are thrown
     * but returned in this array
     * @return signed document object if successfully parsed
     */
    SignedDoc readSignedDocFromStream(InputStream is, List lerr)
            throws DigiDocException;

    /**
     * Reads in a DigiDoc file
     * @param digiSigStream opened stream with Signature data
     * The user must open and close it.
     * @return signed document object if successfully parsed
     */
    Signature readSignature(InputStream digiSigStream)
            throws DigiDocException;

    /**
     * Set temp dir used to cache data files.
     * @param s directory name
     */
    void setTempDir(String s);

}
