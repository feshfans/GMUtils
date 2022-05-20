package com.feshfans.itf;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

public interface CSRUtils {

    /**
     * 返回 PKCS10 证书请求
     * @return
     */
    public String create() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, IOException;

    public void parse(String csr);

}
