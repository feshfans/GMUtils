package com.feshfans;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Provider;

public class Constants {

    public static final Provider bc = new BouncyCastleProvider();

    public static final String sm2CurveName = "sm2p256v1";

}
