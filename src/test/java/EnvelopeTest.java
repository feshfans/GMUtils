import com.feshfans.sm2.SM2AsymmetricKeyWrapper;
import com.feshfans.sm2.SM2CMSEnvelopedDataGenerator;
import com.feshfans.sm2.SM4OutputEncryptor;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.*;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.Test;
import org.zz.gmhelper.cert.SM2CertUtil;

import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Iterator;

public class EnvelopeTest {

    private static BouncyCastleProvider provider = new BouncyCastleProvider();
    // 硬件生成的数字信封
    private static String envelope="MIIBVQYKKoEcz1UGAQQCA6CCAUUwggFBAgEAMYH+MIH7AgEAMGowYTELMAkGA1UEBhMCQ04xMDAuBgNVBAoMJ0NoaW5hIEZpbmFuY2lhbCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTEgMB4GA1UEAwwXQ0ZDQSBBQ1MgVEVTVCBTTTIgT0NBMzECBUA5ORVwMA0GCSqBHM9VAYItAwUABHsweQIhAN7ZTeSmj2+xMvYPdvsCbw5pc/t5uXaPcbblzMTVImN4AiB0U/3iu1zOk/R9Tah9iVtMHq+g1i0g1cUrBbEiPNa6NAQgfq7E8kLiBGd9AD4+WojqRqork97ChxVeEx+nFsSCUQoEEAwxrxVEPQr71xc16jlureQwOwYKKoEcz1UGAQQCATAbBgcqgRzPVQFoBBALAeE5iP2Ipop2puOGRxHVgBA5Zu7DwkU7VLeKymbAypHo";
    // 自己生成的数字信封
    //private static String envelope="MIAGCSqBHM9VBgEEAqCAMIACAQAxgbAwga0CAQAwKTAVMRMwEQYDVQQDDAoqLnRlc3QuY29tAhAAjgT6DAmlFHVgcDyXhan3MAoGCCqBHM9VAYItBHEEjN1NmKDwlI8w2FHNc+kR2XE3fEiEciquH0Cfz5TFs0ZSo1by4ocpzdTRSVfP6qYBkUQ/BmalU5Jz/5J5C+cFTZlYeIxrlf+4gb2zjWR4hdfiwBsFD80QWOD10lw+aAtiHzgeXks5GgedH1WdTms5/jCABgkqhkiG9w0BBwEwGwYHKoEcz1UBaAQQAAAAAAAAAAAAAAAAAAAAAKCABBC5EWY0Dhnxf5YLOaKSq9IjAAAAAAAAAAAAAA==";
    @Test
    public void test() throws IOException, CMSException {

        String pk="00000000000000010000000000000001000000000000000000000000000000000000000000000273MIHGAgECBIHAZIPNPb5+C6Sm+YQs9i6AW2mB91koHdhrHw271sRncG02rIsc4S+M,SNSxMjIH0OxyS3IyDGmUbHVk0J0IEcq5dlPndhYhrlYZyqu9oAeQdXoer+B53vC8,ZI8TV27FqG3QPiCUHfaJjaVZ4pUSGEA1QiBMiivZ7jvSWEDsndA1IFRuF3BfXK74,gfjL2+xHv7vKeaWbwQVuYuH/hKclwQKXE+INlM0FzPVIhXsB8FBjs+R9U6ehm/T8,tqY5g+ojDQw+,";

        //EnvelopedData envelopedData = new EnvelopedData();

        CMSEnvelopedDataParser dataParser = new CMSEnvelopedDataParser(Base64.decode(envelope));
        RecipientInformationStore recipientInfos = dataParser.getRecipientInfos();

        AlgorithmIdentifier contentEncryptionAlgorithm = dataParser.getContentEncryptionAlgorithm();
        String encryptionAlgOID = dataParser.getEncryptionAlgOID();
        OriginatorInformation originatorInfo = dataParser.getOriginatorInfo();
        byte[] encryptionAlgParams = dataParser.getEncryptionAlgParams();
        //AttributeTable unprotectedAttributes = dataParser.getUnprotectedAttributes();

        AlgorithmIdentifier contentEncryptionAlgorithm1 = dataParser.getContentEncryptionAlgorithm();


        System.out.println(encryptionAlgOID);

        Iterator<RecipientInformation> iterator = recipientInfos.iterator();
        if(iterator.hasNext()){
            RecipientInformation next = iterator.next();
            RecipientId rid = next.getRID();

            AlgorithmIdentifier keyEncryptionAlgorithm = next.getKeyEncryptionAlgorithm();

            KeyTransRecipientInformation keyTransRecipientInformation =  (KeyTransRecipientInformation)next;
            //keyTransRecipientInformation.getContent(re)
            System.out.println(next);
        }
    }

    @Test
    public void testMakeSM2Envelope() throws IOException, CertificateException, CMSException {
        byte[] iv={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

        ASN1ObjectIdentifier ID_SM2_PUBKEY_PARAM = new ASN1ObjectIdentifier("1.2.156.10197.1.301");
        ASN1ObjectIdentifier SM4= new ASN1ObjectIdentifier("1.2.156.10197.1.104");

        //要加密的消息
        CMSTypedData cmsTypedData = new CMSProcessableByteArray("test".getBytes(StandardCharsets.UTF_8));


        SM2CMSEnvelopedDataGenerator generator = new SM2CMSEnvelopedDataGenerator();
        // 接收者信息
        X509Certificate x509Certificate = parse();

        BCECPublicKey bcecPublicKey = SM2CertUtil.getBCECPublicKey(x509Certificate);

        SM2AsymmetricKeyWrapper sm2AsymmetricKeyWrapper = new SM2AsymmetricKeyWrapper(x509Certificate, new AlgorithmIdentifier(ID_SM2_PUBKEY_PARAM), bcecPublicKey);
        generator.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(x509Certificate, sm2AsymmetricKeyWrapper).setProvider(provider));
        // 明文加密器
        SM4OutputEncryptor sm4OutputEncryptor = new SM4OutputEncryptor(new IvParameterSpec(iv));
        // 数字信封生成
        CMSEnvelopedData generate = generator.generate(cmsTypedData, sm4OutputEncryptor);

        byte[] encoded = generate.getEncoded();

        System.out.println(Base64.encode(encoded));


        //KeyGenerator.getInstance("SM4")
    }

    private X509Certificate parse() throws CertificateException, FileNotFoundException {

        String filePath = "/Users/feshfans/Downloads/self-sign.cer";
        CertificateFactory instance = CertificateFactory.getInstance("X.509", provider);
        X509Certificate certificate =(X509Certificate) instance.generateCertificate(new FileInputStream(new File(filePath)));


        return (X509Certificate)certificate;
    }

}
