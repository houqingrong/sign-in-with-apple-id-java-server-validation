package com.qingrong.domain;

/**
 * @author HouQingrong
 * @date 2020-04-03 14:34
 */
public class JwsHeader {
    private String kid;
    private String alg;

    public String getKid() {
        return kid;
    }
    public void setKid(String kid) {
        this.kid = kid;
    }
    public String getAlg() {
        return alg;
    }
    public void setAlg(String alg) {
        this.alg = alg;
    }
}
