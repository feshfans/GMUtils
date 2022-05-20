package com.feshfans.sm2;

import com.feshfans.Constants;
import com.feshfans.itf.CSRUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.math.ec.custom.gm.SM2P256V1Curve;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.io.StringWriter;
import java.security.*;
import java.security.spec.ECGenParameterSpec;

public class SM2CSRUtils implements CSRUtils {
    @Override
    public String create() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, IOException {
        //SM2P256V1Curve sm2P256V1Curve = new SM2P256V1Curve();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", Constants.bc);
        generator.initialize(new ECNamedCurveGenParameterSpec(Constants.sm2CurveName));

        KeyPair keyPair = generator.generateKeyPair();
        PublicKey aPublic = keyPair.getPublic();
        PrivateKey aPrivate = keyPair.getPrivate();

        // 生成私钥的字符串
        PemObject pemObject = new PemObject("EC PRIVATE KEY", aPrivate.getEncoded());
        StringWriter writer = new StringWriter();
        PemWriter pemWriter = new PemWriter(writer);
        pemWriter.writeObject(pemObject);
        pemWriter.close();
        writer.close();
        // 打印 pem 格式的私钥
        System.out.println(writer.toString());

        // 创建CSR 请求
        X500Principal principal = new X500Principal("C=CN");

        return null;
    }

    @Override
    public void parse(String csr) {

    }


    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        SM2CSRUtils sm2CSRUtils = new SM2CSRUtils();
        sm2CSRUtils.create();
    }
}
