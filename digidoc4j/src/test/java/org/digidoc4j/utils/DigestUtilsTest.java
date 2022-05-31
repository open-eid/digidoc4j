package org.digidoc4j.utils;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.digidoc4j.DigestAlgorithm;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;

public class DigestUtilsTest {

    @BeforeClass
    public static void setUpStatic() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void ecKeySize224_returnsSha512() throws GeneralSecurityException {
        KeyPair keyPair = generateEcKeyPair("secp224r1");
        Assert.assertEquals(DigestAlgorithm.SHA512, DigestUtils.getRecommendedSignatureDigestAlgorithm((ECPublicKey) keyPair.getPublic()));
    }

    @Test
    public void ecKeySize256_returnsSha256() throws GeneralSecurityException {
        KeyPair keyPair = generateEcKeyPair("secp256r1");
        Assert.assertEquals(DigestAlgorithm.SHA256, DigestUtils.getRecommendedSignatureDigestAlgorithm((ECPublicKey) keyPair.getPublic()));
    }

    @Test
    public void ecKeySize384_returnsSha384() throws GeneralSecurityException {
        KeyPair keyPair = generateEcKeyPair("secp384r1");
        Assert.assertEquals(DigestAlgorithm.SHA384, DigestUtils.getRecommendedSignatureDigestAlgorithm((ECPublicKey) keyPair.getPublic()));
    }

    @Test
    public void ecKeySize521_returnsSha512() throws GeneralSecurityException {
        KeyPair keyPair = generateEcKeyPair("secp521r1");
        Assert.assertEquals(DigestAlgorithm.SHA512, DigestUtils.getRecommendedSignatureDigestAlgorithm((ECPublicKey) keyPair.getPublic()));
    }

    private KeyPair generateEcKeyPair(String algo) throws GeneralSecurityException {
        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec(algo);
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDSA", "BC");
        keyPairGenerator.initialize(ecGenSpec, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

}
