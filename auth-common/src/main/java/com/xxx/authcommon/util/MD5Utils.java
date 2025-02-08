package com.xxx.authcommon.util;

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * MD5工具类
 */
public class MD5Utils {

    /**
     * 返回一个文件的MD5校验值
     *
     * @param file 待校验的文件
     * @return MD5校验值
     * @throws IOException NoSuchAlgorithmException or IOException
     * @author caijianqing, 2013-8-18 下午12:32:32
     */
    public static String md5(final File file) throws IOException {
        FileInputStream in = null;
        String md5 = null;
        try {
            in = new FileInputStream(file);
            md5 = md5(in);
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException e) {
                    throw new RuntimeException(e.getMessage(), e);
                }
            }
        }
        return md5;
    }

    /**
     * 返回一个文件输入流的MD5校验值
     *
     * @param in 输入流，注意这个流将被关闭
     * @return MD5校验值
     * @throws IOException NoSuchAlgorithmException or IOException
     * @author caijianqing, 2013-8-18 下午12:29:23
     */
    public static String md5(final InputStream in) throws IOException {
        try {
            MessageDigest md;
            md = MessageDigest.getInstance("MD5");
            byte[] buf = new byte[32 * 1024];
            int len;
            while ((len = in.read(buf)) != -1) {
                md.update(buf, 0, len);
            }
            byte[] md5 = md.digest();
            return toHexString(md5);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e.getMessage(), e);
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException e2) {
                    // ignore
                }
            }
        }
    }

    /**
     * 返回一个字符窜的MD5校验值
     *
     * @param str 字符窜
     * @return MD5校验值
     * @author caijianqing, 2013-8-18 下午12:33:57
     */
    public static String md5(final String str) {
        String md5;
        try {
            md5 = md5(str.getBytes("UTF-8"));
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
        return md5;
    }

    /**
     * 返回一个字节数组的MD5校验值
     *
     * @param bytes 待校验数据
     * @return MD5校验值
     * @author caijianqing, 2013-8-18 下午12:33:57
     */
    public static String md5(final byte[] bytes) {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("MD5");
            md.update(bytes);
            byte[] md5 = md.digest();
            return toHexString(md5);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    /**
     * 字节转换为HEX表示形式
     *
     * @param bytes byte[]
     * @return HEX表示形式的字符窜
     * @author caijianqing, 2013-8-18 下午12:34:51
     */
    private static String toHexString(final byte[] bytes) {
        StringBuffer sb = new StringBuffer();
        for (byte b : bytes) {
            String hex = Integer.toHexString(b);
            if (hex.length() < 2) {
                sb.append('0').append(hex.charAt(hex.length() - 1));
            } else {
                sb.append(hex.charAt(hex.length() - 2)).append(hex.charAt(hex.length() - 1));
            }
        }
        return sb.toString();
    }
}
