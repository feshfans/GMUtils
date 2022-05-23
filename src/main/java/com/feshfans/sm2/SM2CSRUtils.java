package com.feshfans.sm2;

import com.feshfans.Constants;
import com.feshfans.itf.CSRUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.math.ec.custom.gm.SM2P256V1Curve;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.io.StringWriter;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

public class SM2CSRUtils implements CSRUtils {
    @Override
    public String create() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, IOException, OperatorCreationException {
        //SM2P256V1Curve sm2P256V1Curve = new SM2P256V1Curve();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", Constants.bc);
        generator.initialize(new ECNamedCurveGenParameterSpec(Constants.sm2CurveName));

        KeyPair keyPair = generator.generateKeyPair();
        PublicKey aPublic = keyPair.getPublic();
        PrivateKey aPrivate = keyPair.getPrivate();

        // 生成私钥的字符串
        String private_key = generatePem("PRIVATE KEY", aPrivate.getEncoded());
        // 打印 pem 格式的私钥
        System.out.println(private_key);

        System.out.println("================================");
        // 创建CSR 请求
        X500Principal principal = new X500Principal("C=CN");
        ContentSigner contentSigner = new JcaContentSignerBuilder("SM3withSM2")
                .setProvider(new BouncyCastleProvider()).build(aPrivate);

        PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(principal, aPublic);
        PKCS10CertificationRequest pkcs10CertificationRequest = builder.build(contentSigner);

        String certificate_request = generatePem("CERTIFICATE REQUEST", pkcs10CertificationRequest.getEncoded());
        System.out.println(certificate_request);
        System.out.println(Base64.getEncoder().encodeToString(pkcs10CertificationRequest.getEncoded()));

        return null;
    }

    @Override
    public void parse(String csr) {

    }


    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException, OperatorCreationException {
        SM2CSRUtils sm2CSRUtils = new SM2CSRUtils();
        sm2CSRUtils.create();
    }

    private String generatePem(String type, byte[] encoded) throws IOException {

        PemObject pemObject = new PemObject(type, encoded);

        StringWriter stringWriter = new StringWriter();
        PemWriter writer = new PemWriter(stringWriter);
        writer.writeObject(pemObject);

        writer.close();
        stringWriter.close();

        return stringWriter.toString();
    }
}
