package com.hzdaba.config.shiro;

import org.apache.shiro.codec.Base64;
import org.apache.shiro.codec.Hex;
import org.apache.shiro.util.ByteSource;

import java.io.Serializable;

/**
 * Created by DELL on 2017/12/15.
 */
public class MyByteSource implements ByteSource,Serializable {

    private static final long serialVersionUID = 1157527729380143508L;
    private byte[] bytes;

    public MyByteSource(){}

    public MyByteSource(byte[] bytes){
        this.bytes=bytes;
    }

    @Override
    public byte[] getBytes() {
        return bytes;
    }

    @Override
    public String toHex() {
        if(bytes==null){
            return null;
        }
        return Hex.encodeToString(bytes);
    }

    @Override
    public String toBase64() {
        if(bytes==null){
            return null;
        }
        return Base64.encodeToString(bytes);
    }

    @Override
    public boolean isEmpty() {
        return bytes==null||bytes.length==0;
    }

    public void setBytes(byte[] bytes) {
        this.bytes = bytes;
    }
}
