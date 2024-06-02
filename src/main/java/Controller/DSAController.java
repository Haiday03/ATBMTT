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
import java.util.HashSet;
import java.util.Set;

/**
 *
 * @author PC
 */
public class DSAController {
    
    // Tính a^b mod n
    public static int modPow(int a, int b, int n) {
        int result = 1;
        a = a % n;
        while (b > 0) {
            if ((b & 1) == 1)
                result = (result * a) % n;
            b = b >> 1;
            a = (a * a) % n;
        }
        return result;
    }
    
    // Tính khóa công khai và khóa bí mật
    public static ArrayList<Integer> createKeys(BigInteger p, BigInteger q) {
        BigInteger g = findPrimitiveRoot(p, q);
        SecureRandom random = new SecureRandom();
        BigInteger x = new BigInteger(q.bitLength(), random).mod(q);
        int y = modPow(g.intValue(), x.intValue(), p.intValue());
        ArrayList<Integer> keys = new ArrayList<>();
        keys.add(p.intValue());
        keys.add(q.intValue());
        keys.add(g.intValue());
        keys.add(y);
        keys.add(x.intValue());
        return keys;
    }
    
    // Hàm băm thông điệp
    public static BigInteger hashMessageToInteger(String message) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] messageDigest = md.digest(message.getBytes());
        return new BigInteger(1, messageDigest); // Chuyển byte array thành BigInteger
    }

    // Tạo chữ ký
    public static ArrayList<Integer> createSignature(String str, int g, int p, int q, int x) throws NoSuchAlgorithmException {
        SecureRandom random = new SecureRandom();        
        int k = random.nextInt(q - 1) + 1; // Chọn ngẫu nhiên k từ 1 đến q - 1
        ArrayList<Integer> result = new ArrayList<>();
        
        int r = modPow(g, k, p) % q;
        result.add(r);
        
        BigInteger tmp = hashMessageToInteger(str).add(BigInteger.valueOf(x).multiply(BigInteger.valueOf(r))).mod(BigInteger.valueOf(q));
        
        // Tìm nghịch đảo của k modulo q
        BigInteger kBigInt = BigInteger.valueOf(k);
        BigInteger kInverse = kBigInt.modInverse(BigInteger.valueOf(q));
        
        int s = kInverse.multiply(tmp).mod(BigInteger.valueOf(q)).intValue();
        result.add(s);
        
        return result;
    }

    // Tìm gốc nguyên thủy
    private static BigInteger findPrimitiveRoot(BigInteger p, BigInteger q) {
        BigInteger phi = p.subtract(BigInteger.ONE); // φ(p) = p - 1
        BigInteger potentialRoot = BigInteger.valueOf(2); // Bắt đầu kiểm tra từ 2
        while (potentialRoot.compareTo(p) < 0) {
            boolean isPrimitiveRoot = true;
            for (BigInteger i = BigInteger.valueOf(2); i.compareTo(phi) <= 0; i = i.add(BigInteger.ONE)) {
                if (phi.mod(i).equals(BigInteger.ZERO)) {
                    continue;
                }
                BigInteger power = phi.divide(i);
                if (potentialRoot.modPow(power, p).equals(BigInteger.ONE)) {
                    isPrimitiveRoot = false;
                    break;
                }
            }
            if (isPrimitiveRoot) {
                return potentialRoot.modPow(phi.divide(q), p); // Đảm bảo rằng g thuộc nhóm con có thứ tự là q
            }
            potentialRoot = potentialRoot.add(BigInteger.ONE);
        }
        return BigInteger.ONE.negate(); // Nếu p không là số nguyên tố, trả về giá trị không hợp lệ
    }
    
    public static boolean checkSianature(String str, int r, int s, int q, int p, int g, int y) throws NoSuchAlgorithmException{
        if(r > q || r < 0 || s > q || s < 0)
              return false;
        
        int w = modPow(s, -1, q);
        
        int u1 = (hashMessageToInteger(str).multiply(BigInteger.valueOf(w)).mod(BigInteger.valueOf(q))).intValue();
        
        int u2 = modPow(r, w, q);
        
        int v = (int) ((Math.pow(g, u1) *Math.pow(y, u2))%q);
        
        return v == r;
    }
        
}
