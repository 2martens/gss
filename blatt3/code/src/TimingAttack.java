import java.math.BigInteger;
import java.security.SecureRandom;

/*
 * Source code for GSS assignment 3.2
 * !!! Please run with VM Args -Djava.compiler=NONE -Xint !!!
 * Author: Lino Helms <lino@lino.io>
 * Available online: https://gist.github.com/lino/7b685327bd779e9366ce
 */

/**
 * Encapsulates password checking algorithm
 */
interface PasswordChecker {
    /**
     * Compares two passwords
     * @param a the user input
     * @param b the password to compare with
     * @return
     */
    public boolean checkPassword(char[] a, char[] b);
}

/**
 * Original implmentation from the assignment
 */
class OriginalPasswordChecker implements PasswordChecker {
    public boolean checkPassword(char[] a, char[] b) {
        int i;
        if (a.length != b.length) return false;
        for (i = 0; i < a.length && a[i] == b[i]; i++) ;
        return i == a.length;
    }
}

/**
 * Timing safer implementation
 */
class TimingSafePasswordChecker implements PasswordChecker {
    public boolean checkPassword(char[] a, char[] b) {
        // in java arrays are passed by reference
        char[] innerA, innerB;
        innerA = a.clone();
        innerB = b.clone();
        boolean trap = false;

        // if the array lengths differ, a trap is triggered and the longer
        // array is compared with itself. once triggered, the function cannot
        // return true, but the timing attack is prevented in most cases.

        if (innerA.length != innerB.length) {
            trap = true;
            innerA = innerB.clone();
        }

        int i = 0;
        for (i = 0; i < innerA.length && innerA[i] == innerB[i]; i++);

        return (i == a.length) && (!trap);
    }
}

public class TimingAttack {

    private PasswordChecker pc;
    private SecureRandom random;

    public TimingAttack(PasswordChecker pc) {
        this.random = new SecureRandom();
        this.pc = pc;
    }

    public String getPCClass(){
        return this.pc.getClass().getSimpleName();
    }

    public boolean checkPassword(char[] a, char[] b) {
        return pc.checkPassword(a, b);
    }


    /**
     * Will find out the password length by timing attack for passwords shorter than checkLength
     *
     * @param realPassword
     * @param checkLength max length of password to be checked
     */
    public boolean getLengthByTiming(String realPassword, int checkLength) {

        if (realPassword.length() > checkLength) {
            throw new AssertionError("Cheater!");
        }

        long startTime;
        long[] durations = new long[checkLength];

        char[] originalArray = realPassword.toCharArray();
        char[] compareArray;


        // random compares just to kill initial data noise
        for (int r = 0; r < 5; r++) {
            checkPassword(new char[(int) Math.random() * 5], originalArray);
        }

        for (int i = 0; i < checkLength; i++) {
            compareArray = new char[i];
            startTime = System.nanoTime();
            checkPassword(originalArray, compareArray);
            durations[i] = System.nanoTime() - startTime;
        }

        long maxValue = 0;
        long maxIndex = 0;
        for (int i = 0; i < durations.length; i++) {
            if (durations[i] > maxValue) {
                maxValue = durations[i];
                maxIndex = i;
            }
        }

        if (maxIndex == realPassword.length()) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * Generates random passwords for test suite
     * @return Random String with length between 1 and 100
     */
    public String getRandomPassword() {
        int length = (int) (Math.random() * (501 - 1)); // random length between 1 and 100
        return new BigInteger(length, random).toString(32);
    }

    public static void main(String[] args) {
        TimingAttack[] attacks = new TimingAttack[2];
        attacks[0] = new TimingAttack(new OriginalPasswordChecker());
        attacks[1] = new TimingAttack(new TimingSafePasswordChecker());

        for (TimingAttack atc : attacks) {
            System.out.println("****\nGSS Timing Attack suite with " + atc.getPCClass());

            int correctGuesses = 0;
            int guessCount = 10000;

            for (int i = 0; i < guessCount; i++) {
                if (atc.getLengthByTiming(atc.getRandomPassword(), 101)) {
                    correctGuesses++;
                }
            }

            // echo statistics
            double percent = ((double) correctGuesses / (double) guessCount) * 100.0;
            System.out.println(correctGuesses + " of " + guessCount + " timing attacks successful: " + percent + "%");
        }
    }
}
