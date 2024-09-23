package com.github.mbreban.vault;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

import com.fasterxml.jackson.annotation.JsonProperty;

public class AsymetricKeyVersion {

    @JsonProperty("certificate_chain")
    private String certificateChain;

    @JsonProperty("creation_time")
    private String creationTime;

    @JsonProperty("name")
    private String name;

    @JsonProperty("public_key")
    private String publicKey;

    public String getCertificateChain() {
        return certificateChain;
    }

    public void setCertificateChain(String certificateChain) {
        this.certificateChain = certificateChain;
    }

    public int getCreationTime() {
        // TODO
        return 0;
    }

    public String getCreationTimeString() {
        return creationTime;
    }

    public Date getCreationTimeDate() {
        try {
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
            return sdf.parse(creationTime);
        } catch (ParseException e) {
            e.printStackTrace();
            return null;
        }
    }

    public void setCreationTime(String datetimeCreation) {
        this.creationTime = datetimeCreation;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }
}
