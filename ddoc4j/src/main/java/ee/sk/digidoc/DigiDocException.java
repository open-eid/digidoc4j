package ee.sk.digidoc;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DigiDocException extends Exception {

    private static final Logger LOGGER = LoggerFactory.getLogger(DigiDocException.class);

    /** numeric exception code */
    private int m_code;
    /** nested exception */
    private Throwable m_detail;

    public static final int ERR_OK = 0;
    public static final int ERR_READ_FILE = 10;
    public static final int ERR_WRITE_FILE = 11;
    public static final int ERR_DIGIDOC_BADXML = 12;
    public static final int ERR_DIGIDOC_FORMAT = 13;
    public static final int ERR_DIGIDOC_VERSION = 13;
    public static final int ERR_SIGATURES_EXIST = 14;
    public static final int ERR_UNSUPPORTED = 15;
    public static final int ERR_NOT_INITED = 16;
    public static final int ERR_INVALID_CONFIG = 17;
    public static final int ERR_DIGEST_ALGORITHM = 20;
    public static final int ERR_DIGEST_LENGTH = 21;
    public static final int ERR_REFERENCE_URI = 22;
    public static final int ERR_TRANSFORM_ALGORITHM = 23;
    public static final int ERR_SIGNATURE_METHOD = 24;
    public static final int ERR_CANONICALIZATION_METHOD = 25;
    public static final int ERR_NO_REFERENCES = 26;
    public static final int ERR_DATA_FILE_CONTENT_TYPE = 105;
    public static final int ERR_DATA_FILE_FILE_NAME = 28;
    public static final int ERR_DATA_FILE_ID = 29;
    public static final int ERR_DATA_FILE_MIME_TYPE = 30;
    public static final int ERR_DATA_FILE_SIZE = 31;
    public static final int ERR_DATA_FILE_DIGEST_TYPE = 32;
    public static final int ERR_DATA_FILE_DIGEST_VALUE = 33;
    public static final int ERR_DATA_FILE_ATTR_NAME = 34;
    public static final int ERR_DATA_FILE_ATTR_VALUE = 35;
    public static final int ERR_SIGNATURE_ID = 36;
    public static final int ERR_SIGNATURE_VALUE_ID = 37;
    public static final int ERR_SIGNATURE_VALUE_VALUE = 38;
    public static final int ERR_SIGNERS_CERT = 39;
    public static final int ERR_SIGNING_TIME = 40;
    public static final int ERR_CERT_DIGEST_ALGORITHM = 41;
    public static final int ERR_CERT_SERIAL = 42;
    public static final int ERR_SIGPROP_ID = 43;
    public static final int ERR_SIGPROP_TARGET = 44;
    public static final int ERR_DATE_FORMAT = 45;
    public static final int ERR_SIGPROP_CERT_ID = 46;
    public static final int ERR_RESPONDER_CERT_ID = 47;
    public static final int ERR_REVREFS_URI = 48;
    public static final int ERR_REVREFS_RESP_ID = 49;
    public static final int ERR_REVREFS_PRODUCED_AT = 50;
    public static final int ERR_REVREFS_DIGEST_ALG = 51;
    public static final int ERR_REVREFS_DIGEST = 52;
    public static final int ERR_RESPONDERS_CERT = 53;
    public static final int ERR_CALCULATE_DIGEST = 54;
    public static final int ERR_INIT_LABELS = 55;
    public static final int ERR_INIT_SIG_FAC = 56;
    public static final int ERR_CRYPTO_DRIVER = 57;
    public static final int ERR_CRYPTO_PROVIDER = 58;
    public static final int ERR_READ_TOKEN_INFO = 59;
    public static final int ERR_TOKEN_LOGIN = 60;
    public static final int ERR_SIGN = 61;
    public static final int ERR_READ_CERT = 62;
    public static final int ERR_TOKEN_LOGOUT = 63;
    public static final int ERR_CRYPTO_FINALIZE = 64;
    public static final int ERR_OCSP_REQ_CREATE = 65;
    public static final int ERR_OCSP_REQ_SEND = 65;
    public static final int ERR_OCSP_GET_CONF = 66;
    public static final int ERR_NOT_FAC_INIT = 67;
    public static final int ERR_OCSP_SIGN = 68;
    public static final int ERR_OCSP_UNSUCCESSFULL = 69;
    public static final int ERR_OCSP_VERIFY = 70;
    public static final int ERR_OCSP_NONCE = 71;
    public static final int ERR_OCSP_PARSE = 72;
    public static final int ERR_UTF8_CONVERT = 73;
    public static final int ERR_ENCODING = 74;
    public static final int ERR_PARSE_XML = 75;
    public static final int ERR_DIG_FAC_INIT = 76;
    public static final int ERR_NUMBER_FORMAT = 77;
    public static final int ERR_DATA_FILE_NOT_SIGNED = 78;
    public static final int ERR_DIGEST_COMPARE = 79;
    public static final int ERR_SIG_PROP_NOT_SIGNED = 80;
    public static final int ERR_VERIFY = 81;
    public static final int ERR_CERT_EXPIRED = 82;
    public static final int ERR_NOTARY_DIGEST = 83;
    public static final int ERR_NOTARY_STATUS = 84;
    public static final int ERR_PKCS11_INIT = 85;
    public static final int ERR_CAN_FAC_INIT = 86;
    public static final int ERR_CAN_ERROR = 87;
    public static final int ERR_OCSP_RESP_STATUS = 88;
    public static final int ERR_XML_CONVERT = 89;
    public static final int ERR_NO_CONFIRMATION = 90;
    public static final int ERR_CERT_REVOKED = 91;
    public static final int ERR_CERT_UNKNOWN = 92;
    public static final int ERR_CA_CERT_READ = 93;
    public static final int ERR_UNKNOWN_CA_CERT = 94;
    public static final int ERR_NOT_SIGNED = 98;

    public static final int ERR_XMLENC_ENCPROP_NAME = 99;
    public static final int ERR_XMLENC_ENCPROP_CONTENT = 100;
    public static final int ERR_XMLENC_ENCKEY_CERT = 101;
    public static final int ERR_XMLENC_ENCKEY_ENCRYPTION_METHOD = 102;
    public static final int ERR_XMLENC_ENCDATA_ENCRYPTION_METHOD = 103;
    public static final int ERR_XMLENC_ENCDATA_XMLNS = 104;
    public static final int ERR_XMLENC_NO_ENCRYPTED_DATA = 27;
    public static final int ERR_XMLENC_NO_ENCRYPTED_KEY = 106;
    public static final int ERR_XMLENC_KEY_GEN = 107;
    public static final int ERR_XMLENC_KEY_DECRYPT = 108;
    public static final int ERR_XMLENC_KEY_ENCRYPT = 109;
    public static final int ERR_XMLENC_KEY_STATUS = 110;
    public static final int ERR_XMLENC_DECRYPT = 111;
    public static final int ERR_XMLENC_ENCRYPT = 112;
    public static final int ERR_XMLENC_COMPRESS = 113;
    public static final int ERR_XMLENC_DECOMPRESS = 114;
    public static final int ERR_XMLENC_DATA_STATUS = 115;
    public static final int ERR_NO_PROVIDER = 116;
    public static final int ERR_OCSP_RECPONDER_NOT_TRUSTED = 117;

    public static final int ERR_CREF_ISSUER = 118;
    public static final int ERR_CERTID_TYPE = 119;
    public static final int ERR_CERTVAL_TYPE = 120;
    public static final int ERR_INCLUDE_URI = 121;
    public static final int ERR_TIMESTAMP_ID = 122;
    public static final int ERR_TIMESTAMP_TYPE = 123;
    public static final int ERR_TIMESTAMP_RESP = 124;
    public static final int ERR_TIMESTAMP_FAC_INIT = 125;
    public static final int ERR_TIMESTAMP_VERIFY = 126;
    public static final int ERR_MIMETYPE_FILE = 127;
    public static final int ERR_DIGIDOC_SERVICE = 128;
    public static final int WARN_WEAK_DIGEST = 129;
    public static final int ERR_SIGNERS_CERT_NONREPUD = 162;
    public static final int ERR_SIGVAL_ASN1 = 166;
    public static final int ERR_INPUT_VALUE = 167;
    public static final int ERR_OCSP_UNAUTHORIZED = 163;
    public static final int ERR_POLICY_NONE = 168;
    public static final int ERR_NONCE_POLICY_OID = 169;
    public static final int ERR_NONCE_POLICY_URL = 170;
    public static final int ERR_NONCE_POLICY_HASH = 171;
    public static final int ERR_DF_NAME = 172;
    public static final int ERR_DF_INV_HASH_GOOD_ALT_HASH = 173;
    public static final int ERR_SIGVAL_00 = 174;
    public static final int ERR_TRANSFORMS = 175;
    public static final int ERR_ISSUER_XMLNS = 176;
    public static final int ERR_OLD_VER = 177;
    public static final int ERR_TEST_SIGNATURE = 178;
    public static final int ERR_DATA_FILE_NOT_IN_CONTAINER = 179;
    public static final int ERR_MANIFEST_ENTRY = 180;
    public static final int ERR_MANIFEST_MIME_TYPE = 181;
    public static final int ERR_MULTIPLE_MANIFEST_FILES = 182;

    /**
     * DigiDocException constructor
     * @param code unique error code. Resources bundle
     * contains localized error messages in form ERR_<code>=<message>
     * @param msg english language error description.
     * @param detail stack trace
     */
    public DigiDocException(int code, String msg, Throwable detail) {
        super(msg);
        m_code = code;
        m_detail = detail;
    }

    /**
     * Accessor for error code
     * @return error code
     */
    public int getCode() {
        return m_code;
    }

    /**
     * Determines if this is a signature error
     * @return true if signature is bad
     */
    public boolean isBadSignature() {
        return (m_code == ERR_VERIFY ||
                m_code == ERR_OCSP_VERIFY ||
                m_code == ERR_DIGEST_COMPARE ||
                m_code == ERR_CERT_EXPIRED ||
                m_code == ERR_NOTARY_STATUS ||
                m_code == ERR_DATA_FILE_NOT_SIGNED ||
                m_code == ERR_SIG_PROP_NOT_SIGNED ||
                m_code == ERR_RESPONDERS_CERT ||
                m_code == ERR_NOTARY_DIGEST ||
                m_code == ERR_OCSP_PARSE ||
                m_code == ERR_OCSP_NONCE ||
                m_code == ERR_UNKNOWN_CA_CERT);
    }

    /**
     * Accessor for stack trace
     * @return stack trace
     */
    public Throwable getNestedException() {
        return m_detail;
    }

    /**
     * String converstion
     * @return stringified exception data
     */
    public String toString() {
        StringBuffer sb = new StringBuffer("ERROR: ");
        sb.append(new Integer(m_code).toString());
        if (getMessage() != null) {
            sb.append(" - ");
            sb.append(getMessage());
        }
        return sb.toString();
    }

    public String getMessage() {
        if (m_detail == null) {
            return super.getMessage();
        } else {
            return m_code +
                    super.getMessage() +
                    "; nested exception is: \n\t" +
                    m_detail.toString();
        }
    }

    public void printStackTrace(java.io.PrintStream ps) {
        if (m_detail == null) {
            super.printStackTrace(ps);
        } else {
            synchronized(ps) {
                ps.println(this);
                m_detail.printStackTrace(ps);
            }
        }
    }

    public void printStackTrace(){
        //printStackTrace(System.err);
    }

    public void printStackTrace(java.io.PrintWriter pw) {
        if (m_detail == null) {
            super.printStackTrace(pw);
        } else {
            synchronized(pw) {
                pw.println(this);
                m_detail.printStackTrace(pw);
            }
        }
    }

    /**
     * Factory method to handle excetions
     * @param ex Exception object to use
     * @param code error code
     */
    public static void handleException(Exception ex, int code) throws DigiDocException {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug(ex.toString(), ex);
        }
        throw new DigiDocException(code, ex.getClass().getName(), ex);
    }

}
