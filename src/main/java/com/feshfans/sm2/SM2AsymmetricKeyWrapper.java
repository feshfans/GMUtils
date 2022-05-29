package com.feshfans.sm2;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.operator.AsymmetricKeyWrapper;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.OperatorException;
import org.bouncycastle.operator.jcajce.JceAsymmetricKeyWrapper;
import org.zz.gmhelper.SM2Util;

import java.security.Key;
import java.security.cert.X509Certificate;

public class SM2AsymmetricKeyWrapper extends JceAsymmetricKeyWrapper {

    private BCECPublicKey publicKey;

    public SM2AsymmetricKeyWrapper(X509Certificate x509Certificate, AlgorithmIdentifier algorithmIdentifier, BCECPublicKey publicKey)
    {
        super(algorithmIdentifier,x509Certificate.getPublicKey());
        this.publicKey = publicKey;
    }
    @Override
    public byte[] generateWrappedKey(GenericKey encryptionKey) throws OperatorException {
        try
        {
            //要加密的明文
            byte[] keyEnc = getKeyBytes(encryptionKey);
            byte[] encrypt = SM2Util.encrypt(SM2Engine.Mode.C1C3C2,publicKey, keyEnc);
            return encrypt;
        }
        catch (InvalidCipherTextException e)
        {
            throw new OperatorException("unable to encrypt contents key", e);
        }
    }


    private byte[] getKeyBytes(GenericKey key)
    {
        if (key.getRepresentation() instanceof Key)
        {
            return ((Key)key.getRepresentation()).getEncoded();
        }

        if (key.getRepresentation() instanceof byte[])
        {
            return (byte[])key.getRepresentation();
        }

        throw new IllegalArgumentException("unknown generic key type");
    }
}
