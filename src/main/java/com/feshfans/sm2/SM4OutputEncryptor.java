package com.feshfans.sm2;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.jcajce.io.CipherOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JceGenericKey;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.OutputStream;
import java.security.SecureRandom;

public class SM4OutputEncryptor implements OutputEncryptor {

    private SecretKey encKey;
    private AlgorithmIdentifier algorithmIdentifier;
    private Cipher cipher;
    public static final String ALGORITHM_NAME_ECB_PADDING = "SM4/CBC/PKCS5Padding";
    public SM4OutputEncryptor(IvParameterSpec parameterSpec)
            throws CMSException
    {

        try
        {
            SecureRandom secureRandom = new SecureRandom();
            KeyGenerator keyGen = KeyGenerator.getInstance("SM4", new BouncyCastleProvider());
            keyGen.init(128, secureRandom);

            cipher = Cipher.getInstance(ALGORITHM_NAME_ECB_PADDING, new BouncyCastleProvider());
            encKey = keyGen.generateKey();

            cipher.init(Cipher.ENCRYPT_MODE, encKey, parameterSpec, secureRandom);
            ASN1ObjectIdentifier SM4= new ASN1ObjectIdentifier("1.2.156.10197.1.104");
            algorithmIdentifier = new AlgorithmIdentifier(SM4, new DEROctetString(parameterSpec.getIV()));
        }
        catch (Exception e)
        {
            throw new CMSException("unable to initialize cipher: " + e.getMessage(), e);
        }
    }

    public AlgorithmIdentifier getAlgorithmIdentifier()
    {
        return algorithmIdentifier;
    }

    public OutputStream getOutputStream(OutputStream dOut)
    {
        return new CipherOutputStream(dOut, cipher);
    }

    public GenericKey getKey()
    {
        return new JceGenericKey(algorithmIdentifier, encKey);
    }
}
