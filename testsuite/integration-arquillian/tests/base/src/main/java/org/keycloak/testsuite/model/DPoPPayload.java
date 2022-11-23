package org.keycloak.testsuite.model;

public class DPoPPayload {
    private String jti;
    private String htm;
    private String htu;
    private long iat;

    public String getJti() {
        return jti;
    }

    public void setJti(String jti) {
        this.jti = jti;
    }

    public String getHtm() {
        return htm;
    }

    public void setHtm(String htm) {
        this.htm = htm;
    }

    public String getHtu() {
        return htu;
    }

    public void setHtu(String htu) {
        this.htu = htu;
    }

    public long getIat() {
        return iat;
    }

    public void setIat(long iat) {
        this.iat = iat;
    }
}
