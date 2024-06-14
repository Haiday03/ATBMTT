/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package Controller;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;

/**
 *
 * @author PC
 */
public class DSAController {
    
        /**
         * Phương thức tính lũy thừa a^b mod n
         *
         * @param a Cơ số
         * @param b Số mũ
         * @param n Mẫu số
         * @return Kết quả của a^b mod n
         */
        public static BigInteger modPow(BigInteger a, BigInteger b, BigInteger n) {
            return a.modPow(b, n);
        }

        /**
         * Tạo khóa công khai và khóa bí mật dựa trên p và q
         *
         * @param p Số nguyên tố lớn
         * @param q Số nguyên tố nhỏ, ước của p-1
         * @return Danh sách các giá trị [p, q, g, y, x] trong đó:
         *         p, q: Các giá trị đầu vào
         *         g: Số nguyên cơ sở
         *         y: Khóa công khai
         *         x: Khóa bí mật
         */
        public static ArrayList<BigInteger> createKeys(BigInteger p, BigInteger q) {
            BigInteger g = findPrimitiveRoot(p, q);
            SecureRandom random = new SecureRandom();
            BigInteger x = new BigInteger(q.bitLength(), random).mod(q);
            BigInteger y = g.modPow(x, p);
            ArrayList<BigInteger> keys = new ArrayList<>();
            keys.add(p);
            keys.add(q);
            keys.add(g);
            keys.add(y);
            keys.add(x);
            return keys;
        }

        /**
         * Băm thông điệp thành số nguyên bằng thuật toán SHA-1
         *
         * @param message Thông điệp cần băm
         * @return Giá trị băm của thông điệp dưới dạng số nguyên
         * @throws NoSuchAlgorithmException Nếu không tìm thấy thuật toán băm
         */
        public static BigInteger hashMessageToInteger(String message) throws NoSuchAlgorithmException {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] messageDigest = md.digest(message.getBytes());
            return new BigInteger(1, messageDigest);
        }

        /**
         * Tạo chữ ký số cho thông điệp
         *
         * @param str Thông điệp cần ký
         * @param g Số nguyên cơ sở
         * @param p Số nguyên tố lớn
         * @param q Số nguyên tố nhỏ, ước của p-1
         * @param x Khóa bí mật
         * @return Danh sách chứa các giá trị [r, s] của chữ ký
         * @throws NoSuchAlgorithmException Nếu không tìm thấy thuật toán băm
         */
        public static ArrayList<BigInteger> createSignature(String str, BigInteger g, BigInteger p, BigInteger q, BigInteger x) throws NoSuchAlgorithmException {
            SecureRandom random = new SecureRandom();
            BigInteger k;
            do {
                k = new BigInteger(q.bitLength(), random).mod(q);
            } while (k.equals(BigInteger.ZERO));

            BigInteger r = g.modPow(k, p).mod(q);
            BigInteger s = (k.modInverse(q).multiply(hashMessageToInteger(str).add(x.multiply(r)))).mod(q);

            ArrayList<BigInteger> result = new ArrayList<>();
            result.add(r);
            result.add(s);
            return result;
        }

        /**
         * Tìm căn nguyên thủy g của p
         *
         * @param p Số nguyên tố lớn
         * @param q Số nguyên tố nhỏ, ước của p-1
         * @return Giá trị căn nguyên thủy g
         */
        private static BigInteger findPrimitiveRoot(BigInteger p, BigInteger q) {
            BigInteger phi = p.subtract(BigInteger.ONE);
            BigInteger g = BigInteger.valueOf(2);
            while (true) {
                if (g.modPow(phi.divide(q), p).compareTo(BigInteger.ONE) != 0) {
                    return g;
                }
                g = g.add(BigInteger.ONE);
            }
        }

        /**
         * Kiểm tra chữ ký số của thông điệp
         *
         * @param str Thông điệp cần kiểm tra
         * @param r Phần r của chữ ký
         * @param s Phần s của chữ ký
         * @param q Số nguyên tố nhỏ, ước của p-1
         * @param p Số nguyên tố lớn
         * @param g Số nguyên cơ sở
         * @param y Khóa công khai
         * @return true nếu chữ ký hợp lệ, ngược lại false
         * @throws NoSuchAlgorithmException Nếu không tìm thấy thuật toán băm
         */
        public static boolean checkSignature(String str, BigInteger r, BigInteger s, BigInteger q, BigInteger p, BigInteger g, BigInteger y) throws NoSuchAlgorithmException {
            if (r.compareTo(BigInteger.ZERO) <= 0 || r.compareTo(q) >= 0 || s.compareTo(BigInteger.ZERO) <= 0 || s.compareTo(q) >= 0) {
                return false;
            }
            BigInteger w = s.modInverse(q);
            BigInteger u1 = hashMessageToInteger(str).multiply(w).mod(q);
            BigInteger u2 = r.multiply(w).mod(q);
            BigInteger v = (g.modPow(u1, p).multiply(y.modPow(u2, p)).mod(p)).mod(q);
            return v.equals(r);
        }
}
