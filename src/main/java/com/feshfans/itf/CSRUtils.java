package com.feshfans.itf;

import org.bouncycastle.operator.OperatorCreationException;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

public interface CSRUtils {

    /**
     * 返回 PKCS10 证书请求
     * @return
     */
    public String create() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, IOException, OperatorCreationException;

    public void parse(String csr);

}
